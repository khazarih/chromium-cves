from config import config
import chromadb


def get_client():
    return chromadb.HttpClient(host=config.chroma_host, port=config.chroma_port)


def get_cves_collection():
    return get_client().get_or_create_collection(
        name=config.chroma_cves_collection,
        metadata={"hnsw:space": "cosine"},
    )


def get_patches_collection():
    return get_client().get_or_create_collection(
        name=config.chroma_patches_collection,
        metadata={"hnsw:space": "cosine"},
    )


def upsert_cve(cve_id, description, metadata):
    get_cves_collection().upsert(
        ids=[cve_id],
        documents=[description],
        metadatas=[metadata],
    )


def upsert_cves(ids, documents, metadatas):
    get_cves_collection().upsert(ids=ids, documents=documents, metadatas=metadatas)


def upsert_patch(patch_id, code, metadata):
    get_patches_collection().upsert(
        ids=[patch_id],
        documents=[code],
        metadatas=[metadata],
    )


def upsert_patches(ids, documents, metadatas):
    get_patches_collection().upsert(ids=ids, documents=documents, metadatas=metadatas)


def query_cves(query_text, n_results=5, where=None):
    kwargs = {"query_texts": [query_text], "n_results": n_results}
    if where:
        kwargs["where"] = where
    return get_cves_collection().query(**kwargs)


def query_patches(query_text, n_results=5, where=None):
    kwargs = {"query_texts": [query_text], "n_results": n_results}
    if where:
        kwargs["where"] = where
    return get_patches_collection().query(**kwargs)


def get_existing_cve_ids():
    col = get_cves_collection()
    results = col.get(include=[])
    return set(results["ids"]) if results["ids"] else set()


def get_existing_commit_hashes():
    col = get_patches_collection()
    results = col.get(include=["metadatas"])
    return {
        m.get("commit_hash") for m in results["metadatas"] if m and m.get("commit_hash")
    }


def get_cve_metadata(cve_id):
    col = get_cves_collection()
    results = col.get(ids=[cve_id], include=["metadatas", "documents"])
    if results["ids"]:
        return {
            "id": results["ids"][0],
            "document": results["documents"][0],
            "metadata": results["metadatas"][0],
        }
    return None
