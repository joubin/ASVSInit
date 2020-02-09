import os
import shutil
from unittest import TestCase

from Stage import Stage


class TestStage(TestCase):







    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if os.path.exists(Stage.get_downloads_location()):
            shutil.rmtree(Stage.get_downloads_location())

    def setUp(self) -> None:
        super().setUp()

    def test_download_files(self):
        stage = Stage()
        stage.download_files()
        if not os.path.exists(stage.get_downloads_location()):
            self.fail()

    def test_get_taxonomy(self):
        self.assertTrue(True)

    def test_parse(self):
        self.assertTrue(True)

    def tearDown(self) -> None:
        super().tearDown()
        self.downloads = os.getcwd().join("downloads")
        if os.path.exists(self.downloads):
            os.removedirs(self.downloads)
        else:
            print("nothing")

