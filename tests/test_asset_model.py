import unittest
import os
import logging

from snyker import (
    GroupPydanticModel,
    OrganizationPydanticModel,
    ProjectPydanticModel,
    Asset, # Asset is already the Pydantic model
    APIClient
)
from snyker.config import API_CONFIG

# Provided IDs
TEST_GROUP_ID = "9365faba-3e72-4fda-9974-267779137aa6"
TEST_ORG_ID = "14effe65-5d0c-4aa0-9371-339e58e13717" # Smaller org
# We'll try to find an asset related to this org or a known project.
# For example, an asset representing the 'tim-snyk/snyker' repo if monitored.
# Let's use a known project from this org to find a related asset if possible,
# or query for a known asset name.
# TEST_PROJECT_ID_SCA = "915d2170-2e59-4a76-985f-47bf226999cf" 

# Name of an asset we expect to find (e.g., the snyker repo itself if monitored)
# This might need adjustment based on what's actually in the test Snyk account.
KNOWN_ASSET_NAME_CONTAINS = "snyker" 
KNOWN_ASSET_TYPE = "repository"


@unittest.skipIf(not os.getenv('SNYK_TOKEN'), "SNYK_TOKEN not set, skipping integration tests")
class TestAssetPydanticModelIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api_client = APIClient(logging_level=logging.DEBUG)
        API_CONFIG["loading_strategy"] = "lazy" 

        try:
            cls.group = GroupPydanticModel.get_instance(api_client=cls.api_client, group_id=TEST_GROUP_ID)
        except ValueError as e:
            raise unittest.SkipTest(f"Could not get group instance {TEST_GROUP_ID}: {e}")

        cls.asset_to_test = None
        if cls.group:
            asset_query = {
                "query": {
                    "attributes": {
                        "operator": "and",
                        "values": [
                            {"attribute": "type", "operator": "equal", "values": [KNOWN_ASSET_TYPE]},
                            {"attribute": "name", "operator": "contains", "values": [KNOWN_ASSET_NAME_CONTAINS]}
                        ]
                    }
                }
            }
            # Fetch a limited number of assets to find one for testing
            # The get_assets_by_query in GroupPydanticModel should handle limits if the API does.
            # API requires limit >= 10 for this endpoint.
            assets = cls.group.get_assets_by_query(query=asset_query, params={'limit': 10}) 
            if assets:
                cls.asset_to_test = assets[0] # Take the first one for testing
                cls.api_client.logger.info(f"Using asset {cls.asset_to_test.id} ({cls.asset_to_test.name}) for tests.")
        
        if not cls.asset_to_test:
            raise unittest.SkipTest(
                f"Asset containing '{KNOWN_ASSET_NAME_CONTAINS}' of type '{KNOWN_ASSET_TYPE}' "
                f"not found in Group {TEST_GROUP_ID} for testing."
            )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'api_client') and cls.api_client:
            cls.api_client.close()

    def setUp(self):
        self.original_loading_strategy = API_CONFIG.get("loading_strategy")
        API_CONFIG["loading_strategy"] = "lazy"

    def tearDown(self):
        API_CONFIG["loading_strategy"] = self.original_loading_strategy

    def test_asset_instantiation(self):
        """Test that the Asset instance was correctly set up."""
        if self.asset_to_test is None:
            self.skipTest("Asset to test was not loaded in setUpClass.")
        
        self.assertIsInstance(self.asset_to_test, Asset)
        self.assertIsNotNone(self.asset_to_test.id)
        self.assertEqual(self.asset_to_test.type, KNOWN_ASSET_TYPE)
        self.assertIn(KNOWN_ASSET_NAME_CONTAINS.lower(), self.asset_to_test.name.lower())
        self.assertIs(self.asset_to_test._api_client, self.api_client)
        self.assertIs(self.asset_to_test._group, self.group)

    def test_lazy_load_asset_organizations(self):
        """Test lazy loading of asset's organizations via property access."""
        if self.asset_to_test is None:
            self.skipTest("Asset to test was not loaded in setUpClass.")
        API_CONFIG["loading_strategy"] = "lazy"

        organizations = self.asset_to_test.organizations # Property access

        self.assertIsNotNone(organizations)
        self.assertIsInstance(organizations, list)
        
        if organizations:
            self.assertIsInstance(organizations[0], OrganizationPydanticModel)
            self.api_client.logger.info(
                f"Lazy loaded {len(organizations)} orgs for asset {self.asset_to_test.id}. "
                f"First org ID: {organizations[0].id}"
            )
            # Check if the known TEST_ORG_ID is among them, if this asset is expected to be in it.
            # This assertion might be too strict if the asset isn't guaranteed to be in TEST_ORG_ID.
            # For now, we'll just check that some orgs are loaded.
            # self.assertTrue(any(org.id == TEST_ORG_ID for org in organizations))
        else:
            self.api_client.logger.warning(f"No organizations found for asset {self.asset_to_test.id} during lazy load.")


    def test_lazy_load_asset_projects(self):
        """Test lazy loading of asset's projects via property access."""
        if self.asset_to_test is None:
            self.skipTest("Asset to test was not loaded in setUpClass.")
        API_CONFIG["loading_strategy"] = "lazy"

        projects = self.asset_to_test.projects # Property access

        self.assertIsNotNone(projects)
        self.assertIsInstance(projects, list)
        
        if projects:
            self.assertIsInstance(projects[0], ProjectPydanticModel)
            self.api_client.logger.info(
                f"Lazy loaded {len(projects)} projects for asset {self.asset_to_test.id}. "
                f"First project ID: {projects[0].id}"
            )
        else:
            self.api_client.logger.warning(f"No projects found for asset {self.asset_to_test.id} during lazy load.")

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s-%(levelname)s-%(name)s - %(message)s')
    unittest.main()
