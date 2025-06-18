import unittest
import os
import logging

from snyker import GroupPydanticModel, OrganizationPydanticModel, ProjectPydanticModel, APIClient
from snyker.config import API_CONFIG

# Provided IDs
TEST_GROUP_ID = "9365faba-3e72-4fda-9974-267779137aa6" # Keep the same group
TEST_ORG_ID = "14effe65-5d0c-4aa0-9371-339e58e13717" # New smaller OrgID
TEST_PROJECT_ID_SCA = "915d2170-2e59-4a76-985f-47bf226999cf" # New SCA Project ID in this Org
TEST_PROJECT_ID_SAST = "73ee3b63-f372-44a9-8b06-5a708d5c5def" # New SAST Project ID in this Org

@unittest.skipIf(not os.getenv('SNYK_TOKEN'), "SNYK_TOKEN not set, skipping integration tests")
class TestOrganizationPydanticModelIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Setup APIClient and base Group once for all tests in this class
        # This reduces repeated Group/Org fetching if Org details don't change between tests
        cls.api_client = APIClient(logging_level=logging.DEBUG) # Use DEBUG for detailed logs
        
        # Ensure the Group is fetched once
        try:
            cls.group = GroupPydanticModel.get_instance(api_client=cls.api_client, group_id=TEST_GROUP_ID)
        except ValueError as e:
            raise unittest.SkipTest(f"Could not get group instance {TEST_GROUP_ID}, skipping Org tests: {e}")

        # Fetch the specific organization to be tested
        # Option 1: Iterate through group.organizations (if lazy loading is default or set for this setup)
        # Option 2: Use a more direct fetch if available and reliable
        cls.org_to_test = None
        if cls.group:
            # Ensure orgs are fetched if not already by property access (respects loading_strategy)
            API_CONFIG["loading_strategy"] = "lazy" # Ensure lazy for this setup part
            orgs = cls.group.organizations 
            for org_instance in orgs:
                if org_instance.id == TEST_ORG_ID:
                    cls.org_to_test = org_instance
                    break
        
        if not cls.org_to_test:
            raise unittest.SkipTest(f"Test Organization {TEST_ORG_ID} not found in Group {TEST_GROUP_ID}, skipping tests.")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'api_client') and cls.api_client:
            cls.api_client.close()

    def setUp(self):
        # Store original loading strategy to restore it after each test
        self.original_loading_strategy = API_CONFIG.get("loading_strategy")
        # Most tests here will focus on lazy loading for Org's children
        API_CONFIG["loading_strategy"] = "lazy"


    def tearDown(self):
        # Restore original loading strategy
        API_CONFIG["loading_strategy"] = self.original_loading_strategy


    def test_organization_instantiation(self):
        """Test that the OrganizationPydanticModel instance was correctly set up."""
        if self.org_to_test is None:
            self.skipTest("Organization to test was not loaded in setUpClass.")
        self.assertEqual(self.org_to_test.id, TEST_ORG_ID)
        self.assertIsInstance(self.org_to_test.name, str)
        self.assertTrue(len(self.org_to_test.name) > 0)
        self.assertIs(self.org_to_test._api_client, self.api_client)
        self.assertIs(self.org_to_test._group, self.group)

    def test_fetch_projects_minimal_scope(self):
        """Test fetching projects with a narrow scope (e.g., limit to 1)."""
        if self.org_to_test is None:
            self.skipTest("Organization to test was not loaded in setUpClass.")
        API_CONFIG["loading_strategy"] = "lazy" # Ensure lazy for explicit fetch test

        # Fetch with a limit. Note: Check Snyk API docs if /orgs/{orgId}/projects supports 'limit'.
        # If not, this test might fetch default (e.g., 100) or fail if 'limit' is invalid.
        # API requires limit to be >= 10 and a multiple of 10 for this endpoint.
        fetched_projects = self.org_to_test.fetch_projects(params={'limit': 10})

        self.assertIsNotNone(fetched_projects)
        self.assertIsInstance(fetched_projects, list)
        
        if fetched_projects:
            # Original assertion removed based on clarification that 'limit' in params
            # is for API per-page configuration, and fetch_projects should return all matching items.
            # self.assertTrue(len(fetched_projects) <= 10, "Expected 0-10 projects with limit=10")
            self.assertIsInstance(fetched_projects[0], ProjectPydanticModel)
            self.api_client.logger.info(f"Fetched project(s): {[p.id for p in fetched_projects]}")
        else:
            self.api_client.logger.info(f"No projects returned for org {self.org_to_test.id} with limit=10.")

    def test_lazy_load_projects_property_access(self):
        """Test lazy loading of projects via property access."""
        if self.org_to_test is None:
            self.skipTest("Organization to test was not loaded in setUpClass.")
        API_CONFIG["loading_strategy"] = "lazy"

        # Access projects property to trigger lazy loading
        projects = self.org_to_test.projects 

        self.assertIsNotNone(projects)
        self.assertIsInstance(projects, list)
        
        if projects:
            self.assertIsInstance(projects[0], ProjectPydanticModel)
            # Check if one of our known project IDs is in the list
            found_sca = any(p.id == TEST_PROJECT_ID_SCA for p in projects)
            found_sast = any(p.id == TEST_PROJECT_ID_SAST for p in projects)
            
            if not (found_sca or found_sast):
                fetched_project_ids = [p.id for p in projects]
                self.api_client.logger.error(
                    f"TEST_PROJECT_ID_SCA ('{TEST_PROJECT_ID_SCA}') or "
                    f"TEST_PROJECT_ID_SAST ('{TEST_PROJECT_ID_SAST}') not found in {len(fetched_project_ids)} fetched projects "
                    f"for org {self.org_to_test.id}. Fetched IDs: {fetched_project_ids[:20]}..." # Log first 20
                )
            self.assertTrue(found_sca or found_sast, 
                            f"Neither TEST_PROJECT_ID_SCA ({TEST_PROJECT_ID_SCA}) nor "
                            f"TEST_PROJECT_ID_SAST ({TEST_PROJECT_ID_SAST}) found in loaded projects for org {self.org_to_test.id}.")
            
            if found_sca:
                 self.api_client.logger.info(f"Found SCA project {TEST_PROJECT_ID_SCA} in lazy loaded projects.")
            if found_sast:
                 self.api_client.logger.info(f"Found SAST project {TEST_PROJECT_ID_SAST} in lazy loaded projects.")
        else:
            self.api_client.logger.warning(f"No projects found for org {self.org_to_test.id} during lazy load test.")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s-%(levelname)s-%(name)s - %(message)s')
    unittest.main()
