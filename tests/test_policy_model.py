import unittest
import os
import logging

from snyker import (
    GroupPydanticModel,
    OrganizationPydanticModel,
    PolicyPydanticModel,
    APIClient
)
from snyker.config import API_CONFIG

# Provided IDs
TEST_GROUP_ID = "9365faba-3e72-4fda-9974-267779137aa6"

@unittest.skipIf(not os.getenv('SNYK_TOKEN'), "SNYK_TOKEN not set, skipping integration tests")
class TestPolicyPydanticModelIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api_client = APIClient(logging_level=logging.DEBUG)
        API_CONFIG["loading_strategy"] = "lazy" # Ensure lazy for setup

        try:
            group = GroupPydanticModel.get_instance(api_client=cls.api_client, group_id=TEST_GROUP_ID)
        except ValueError as e:
            raise unittest.SkipTest(f"Could not get group instance {TEST_GROUP_ID}: {e}")
        
        if not group:
             raise unittest.SkipTest(f"Group instance {TEST_GROUP_ID} is None after get_instance call.")

        cls.all_orgs_in_group = group.organizations # Property access, respects lazy
        if not cls.all_orgs_in_group:
            cls.api_client.logger.warning(f"No organizations found in Group {TEST_GROUP_ID} during setUpClass. Policy tests might not find any policies.")


    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'api_client') and cls.api_client:
            cls.api_client.close()

    def setUp(self):
        self.original_loading_strategy = API_CONFIG.get("loading_strategy")
        API_CONFIG["loading_strategy"] = "lazy" 

    def tearDown(self):
        API_CONFIG["loading_strategy"] = self.original_loading_strategy

    def test_fetch_policies_across_orgs(self):
        """Test fetching policies for all orgs in the group."""
        if not self.all_orgs_in_group:
            self.skipTest(f"No organizations found in Group {TEST_GROUP_ID} to test policy fetching.")

        API_CONFIG["loading_strategy"] = "lazy"
        found_any_policies = False

        for org in self.all_orgs_in_group:
            self.api_client.logger.info(f"Testing fetch_policies for Org ID: {org.id} ({org.name})")
            # The /orgs/{org_id}/policies endpoint usually supports limit
            fetched_policies = org.fetch_policies(params={'limit': 10}) 

            self.assertIsNotNone(fetched_policies)
            self.assertIsInstance(fetched_policies, list)
            
            if fetched_policies:
                found_any_policies = True
                self.assertIsInstance(fetched_policies[0], PolicyPydanticModel)
                self.api_client.logger.info(
                    f"Fetched {len(fetched_policies)} policies for org {org.id}. First policy ID: {fetched_policies[0].id}, Name: {fetched_policies[0].name}"
                )
                # Verify basic attributes of the first policy
                self.assertIsNotNone(fetched_policies[0].id)
                self.assertIsNotNone(fetched_policies[0].type)
                # Name can be None for some policies (e.g. legacy security policies)
                # self.assertIsNotNone(fetched_policies[0].name) 
            else:
                self.api_client.logger.info(f"No policies returned for org {org.id} with limit=10.")
        
        if not found_any_policies:
            self.api_client.logger.warning("No policies found in any organization within the test group.")


    def test_lazy_load_policies_property_access_across_orgs(self):
        """Test lazy loading of policies via property access for all orgs."""
        if not self.all_orgs_in_group:
            self.skipTest(f"No organizations found in Group {TEST_GROUP_ID} to test policy property access.")

        API_CONFIG["loading_strategy"] = "lazy"
        found_any_policies = False

        for org in self.all_orgs_in_group:
            self.api_client.logger.info(f"Testing lazy .policies access for Org ID: {org.id} ({org.name})")
            policies = org.policies # Access property

            self.assertIsNotNone(policies)
            self.assertIsInstance(policies, list)
            
            if policies:
                found_any_policies = True
                self.assertIsInstance(policies[0], PolicyPydanticModel)
                self.api_client.logger.info(
                    f"Lazy loaded {len(policies)} policies for org {org.id}. First policy ID: {policies[0].id}, Name: {policies[0].name}"
                )
            else:
                self.api_client.logger.info(f"No policies found for org {org.id} via property access.")
        
        if not found_any_policies:
            self.api_client.logger.warning("No policies found via property access in any organization within the test group.")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s-%(levelname)s-%(name)s - %(message)s')
    unittest.main()
