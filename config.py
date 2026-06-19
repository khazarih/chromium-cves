from dotenv import load_dotenv
import os


class Config:
    def __init__(self):
        load_dotenv()
        self.cvelistV5_path = os.environ.get("cvelistV5_path", None)
        self.cves = self.cvelistV5_path + "/cves"
        self.chroma_host = os.environ.get("CHROMA_HOST", "localhost")
        self.chroma_port = int(os.environ.get("CHROMA_PORT", "8001"))
        self.chroma_cves_collection = os.environ.get(
            "CHROMA_CVES_COLLECTION", "chromium_cves"
        )
        self.chroma_patches_collection = os.environ.get(
            "CHROMA_PATCHES_COLLECTION", "chromium_patches"
        )


config = Config()
