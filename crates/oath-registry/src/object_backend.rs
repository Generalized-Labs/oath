use anyhow::{Context, Result};
use object_store::{
    ObjectStore, ObjectStoreExt, PutMode, PutOptions, aws::AmazonS3Builder,
    gcp::GoogleCloudStorageBuilder, local::LocalFileSystem, path::Path as ObjectPath,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Debug, Clone)]
pub enum ObjectBackendConfig {
    Local {
        root: PathBuf,
    },
    S3 {
        bucket: String,
        endpoint: Option<String>,
    },
    Gcs {
        bucket: String,
    },
}

#[derive(Clone)]
pub struct ArtifactStore {
    primary: Arc<dyn ObjectStore>,
    replicas: Vec<Arc<dyn ObjectStore>>,
}

impl ArtifactStore {
    pub fn new(primary: Arc<dyn ObjectStore>) -> Self {
        Self {
            primary,
            replicas: Vec::new(),
        }
    }

    pub fn with_replicas(
        primary: Arc<dyn ObjectStore>,
        replicas: Vec<Arc<dyn ObjectStore>>,
    ) -> Self {
        Self { primary, replicas }
    }

    async fn put_one(store: &Arc<dyn ObjectStore>, path: &ObjectPath, bytes: &[u8]) -> Result<()> {
        let options = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match store.put_opts(path, bytes.to_vec().into(), options).await {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let existing = store.get(path).await?.bytes().await?;
                anyhow::ensure!(
                    existing.as_ref() == bytes,
                    "immutable object digest collision"
                );
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn put_immutable(&self, digest: &str, bytes: &[u8]) -> Result<()> {
        let path = ObjectPath::from(digest);
        Self::put_one(&self.primary, &path, bytes).await?;
        for replica in &self.replicas {
            Self::put_one(replica, &path, bytes).await?;
        }
        Ok(())
    }

    pub async fn get(&self, digest: &str) -> Result<Vec<u8>> {
        let path = ObjectPath::from(digest);
        match self.primary.get(&path).await {
            Ok(result) => return Ok(result.bytes().await?.to_vec()),
            Err(object_store::Error::NotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        for replica in &self.replicas {
            match replica.get(&path).await {
                Ok(result) => {
                    let bytes = result.bytes().await?.to_vec();
                    Self::put_one(&self.primary, &path, &bytes).await?;
                    return Ok(bytes);
                }
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("artifact {digest} was not found in primary or replica stores")
    }
}

impl ObjectBackendConfig {
    pub fn from_env(default_root: PathBuf) -> Result<Self> {
        match std::env::var("OATH_OBJECT_BACKEND")
            .unwrap_or_else(|_| "local".into())
            .as_str()
        {
            "local" => Ok(Self::Local { root: default_root }),
            "s3" | "r2" => Ok(Self::S3 {
                bucket: std::env::var("OATH_OBJECT_BUCKET")
                    .context("OATH_OBJECT_BUCKET is required")?,
                endpoint: std::env::var("OATH_OBJECT_ENDPOINT").ok(),
            }),
            "gcs" => Ok(Self::Gcs {
                bucket: std::env::var("OATH_OBJECT_BUCKET")
                    .context("OATH_OBJECT_BUCKET is required")?,
            }),
            backend => anyhow::bail!("unsupported object backend {backend}"),
        }
    }
}

pub fn build(config: ObjectBackendConfig) -> Result<Arc<dyn ObjectStore>> {
    match config {
        ObjectBackendConfig::Local { root } => {
            std::fs::create_dir_all(&root)?;
            Ok(Arc::new(LocalFileSystem::new_with_prefix(root)?))
        }
        ObjectBackendConfig::S3 { bucket, endpoint } => {
            let mut builder = AmazonS3Builder::from_env().with_bucket_name(bucket);
            if let Some(endpoint) = endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            Ok(Arc::new(builder.build()?))
        }
        ObjectBackendConfig::Gcs { bucket } => Ok(Arc::new(
            GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(bucket)
                .build()?,
        )),
    }
}

pub fn artifact_store_from_env(default_root: PathBuf) -> Result<ArtifactStore> {
    let primary = build(ObjectBackendConfig::from_env(default_root.clone())?)?;
    let Some(backend) = std::env::var("OATH_OBJECT_REPLICA_BACKEND").ok() else {
        return Ok(ArtifactStore::new(primary));
    };
    let replica = match backend.as_str() {
        "local" => ObjectBackendConfig::Local {
            root: std::env::var_os("OATH_OBJECT_REPLICA_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| default_root.with_extension("replica")),
        },
        "s3" | "r2" => ObjectBackendConfig::S3 {
            bucket: std::env::var("OATH_OBJECT_REPLICA_BUCKET")
                .context("OATH_OBJECT_REPLICA_BUCKET is required")?,
            endpoint: std::env::var("OATH_OBJECT_REPLICA_ENDPOINT").ok(),
        },
        "gcs" => ObjectBackendConfig::Gcs {
            bucket: std::env::var("OATH_OBJECT_REPLICA_BUCKET")
                .context("OATH_OBJECT_REPLICA_BUCKET is required")?,
        },
        value => anyhow::bail!("unsupported replica object backend {value}"),
    };
    Ok(ArtifactStore::with_replicas(primary, vec![build(replica)?]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    #[test]
    fn local_backend_builds_for_offline_tests() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            build(ObjectBackendConfig::Local {
                root: dir.path().into()
            })
            .is_ok()
        );
    }

    #[tokio::test]
    async fn replicates_writes_to_all_stores() {
        let primary: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let replica: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = ArtifactStore::with_replicas(primary.clone(), vec![replica.clone()]);
        store.put_immutable("digest", b"artifact").await.unwrap();
        let path = ObjectPath::from("digest");
        assert_eq!(
            primary
                .get(&path)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"artifact"
        );
        assert_eq!(
            replica
                .get(&path)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"artifact"
        );
    }

    #[tokio::test]
    async fn reads_from_replica_and_repairs_primary() {
        let primary: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let replica: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let path = ObjectPath::from("digest");
        replica
            .put(&path, b"artifact".to_vec().into())
            .await
            .unwrap();
        let store = ArtifactStore::with_replicas(primary.clone(), vec![replica]);
        assert_eq!(store.get("digest").await.unwrap(), b"artifact");
        assert_eq!(
            primary
                .get(&path)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"artifact"
        );
    }
}
