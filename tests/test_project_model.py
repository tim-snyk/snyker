import unittest
import os
import logging

from snyker import (
    GroupPydanticModel,
    OrganizationPydanticModel,
    ProjectPydanticModel,
    IssuePydanticModel,
    APIClient
)
from snyker.config import API_CONFIG

# Provided IDs
TEST_GROUP_ID = "9365faba-3e72-4fda-9974-267779137aa6"
TEST_ORG_ID = "14effe65-5d0c-4aa0-9371-339e58e13717"
TEST_PROJECT_ID_SCA = "915d2170-2e59-4a76-985f-47bf226999cf" # SCA project in the new TEST_ORG_ID
# TEST_PROJECT_ID_SAST = "73ee3b63-f372-44a9-8b06-5a708d5c5def" # SAST project

@unittest.skipIf(not os.getenv('SNYK_TOKEN'), "SNYK_TOKEN not set, skipping integration tests")
class TestProjectPydanticModelIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api_client = APIClient(logging_level=logging.DEBUG)
        API_CONFIG["loading_strategy"] = "lazy" # Ensure lazy for setup

        try:
            group = GroupPydanticModel.get_instance(api_client=cls.api_client, group_id=TEST_GROUP_ID)
        except ValueError as e:
            raise unittest.SkipTest(f"Could not get group instance {TEST_GROUP_ID}: {e}")

        org_to_test = None
        if group:
            orgs = group.organizations # Property access, respects lazy
            for org_instance in orgs:
                if org_instance.id == TEST_ORG_ID:
                    org_to_test = org_instance
                    break
        
        if not org_to_test:
            raise unittest.SkipTest(f"Test Organization {TEST_ORG_ID} not found in Group {TEST_GROUP_ID}.")
        
        cls.org_to_test = org_to_test # Assign to class attribute

        project_to_test = None
        if cls.org_to_test:
            projects = cls.org_to_test.projects # Property access, respects lazy
            for proj_instance in projects:
                if proj_instance.id == TEST_PROJECT_ID_SCA:
                    project_to_test = proj_instance
                    break
        
        if not project_to_test:
            # Try fetching the specific project directly if not found in the initial list
            # This can happen if the org has many projects and default pagination limit was hit
            cls.api_client.logger.info(f"Project {TEST_PROJECT_ID_SCA} not in initial list, trying direct fetch.")
            project_to_test = cls.org_to_test.get_specific_project(project_id=TEST_PROJECT_ID_SCA)

        if not project_to_test:
            raise unittest.SkipTest(f"Test Project {TEST_PROJECT_ID_SCA} not found in Org {TEST_ORG_ID}.")
        
        cls.project_to_test = project_to_test


    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'api_client') and cls.api_client:
            cls.api_client.close()

    def setUp(self):
        self.original_loading_strategy = API_CONFIG.get("loading_strategy")
        API_CONFIG["loading_strategy"] = "lazy" # Default to lazy for most tests

    def tearDown(self):
        API_CONFIG["loading_strategy"] = self.original_loading_strategy

    def test_project_instantiation(self):
        """Test that the ProjectPydanticModel instance was correctly set up."""
        if self.project_to_test is None:
            self.skipTest("Project to test was not loaded in setUpClass.")
        
        self.assertEqual(self.project_to_test.id, TEST_PROJECT_ID_SCA)
        self.assertIsInstance(self.project_to_test.name, str)
        self.assertTrue(len(self.project_to_test.name) > 0)
        self.assertIs(self.project_to_test._api_client, self.api_client)
        self.assertIs(self.project_to_test._organization, self.org_to_test)

    def test_fetch_issues_minimal_scope(self):
        """Test fetching issues with a narrow scope (e.g., limit to 1)."""
        if self.project_to_test is None:
            self.skipTest("Project to test was not loaded in setUpClass.")
        API_CONFIG["loading_strategy"] = "lazy"

        # Project.fetch_issues delegates to Organization.fetch_issues with filters.
        # The 'limit' here applies to the org-level issue fetch, filtered for this project.
        # Snyk API for org-level issues with project filter might have its own limit behavior.
        # The /orgs/{org_id}/issues endpoint supports `scan_item.id` and `scan_item.type` filters.
        # It also supports `limit`.
        fetched_issues = self.project_to_test.fetch_issues(params={'limit': 10})

        self.assertIsNotNone(fetched_issues)
        self.assertIsInstance(fetched_issues, list)
        
        if fetched_issues:
            self.assertTrue(len(fetched_issues) <= 10)
            self.assertIsInstance(fetched_issues[0], IssuePydanticModel)
            self.api_client.logger.info(f"Fetched issue(s) for project {self.project_to_test.id}: {[i.id for i in fetched_issues]}")
        else:
            self.api_client.logger.info(f"No issues returned for project {self.project_to_test.id} with limit=10.")

        # Verify that the project's internal _issues list is populated
        self.assertIsNotNone(self.project_to_test._issues)
        self.assertEqual(len(self.project_to_test._issues or []), len(fetched_issues or []))


    def test_lazy_load_issues_property_access(self):
        """Test lazy loading of issues via property access."""
        if self.project_to_test is None:
            self.skipTest("Project to test was not loaded in setUpClass.")
        API_CONFIG["loading_strategy"] = "lazy"

        # Access issues property to trigger lazy loading
        issues = self.project_to_test.issues 

        self.assertIsNotNone(issues)
        self.assertIsInstance(issues, list)
        
        if issues:
            self.assertIsInstance(issues[0], IssuePydanticModel)
            self.api_client.logger.info(f"Lazy loaded {len(issues)} issues for project {self.project_to_test.id}. First issue ID: {issues[0].id}")
        else:
            self.api_client.logger.warning(f"No issues found for project {self.project_to_test.id} during lazy load by property.")

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s-%(levelname)s-%(name)s - %(message)s')
    unittest.main()
