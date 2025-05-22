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
TEST_PROJECT_ID_SCA = "915d2170-2e59-4a76-985f-47bf226999cf" 

@unittest.skipIf(not os.getenv('SNYK_TOKEN'), "SNYK_TOKEN not set, skipping integration tests")
class TestIssuePydanticModelIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api_client = APIClient(logging_level=logging.DEBUG)
        API_CONFIG["loading_strategy"] = "lazy" 

        try:
            group = GroupPydanticModel.get_instance(api_client=cls.api_client, group_id=TEST_GROUP_ID)
        except ValueError as e:
            raise unittest.SkipTest(f"Could not get group instance {TEST_GROUP_ID}: {e}")
        
        cls.group = group # Assign to class attribute

        org_to_test = None
        if cls.group:
            orgs = cls.group.organizations 
            for org_instance in orgs:
                if org_instance.id == TEST_ORG_ID:
                    org_to_test = org_instance
                    break
        
        if not org_to_test:
            raise unittest.SkipTest(f"Test Organization {TEST_ORG_ID} not found in Group {TEST_GROUP_ID}.")
        cls.org_to_test = org_to_test

        project_to_test = None
        if cls.org_to_test:
            projects = cls.org_to_test.projects
            for proj_instance in projects:
                if proj_instance.id == TEST_PROJECT_ID_SCA:
                    project_to_test = proj_instance
                    break
        
        if not project_to_test:
            project_to_test = cls.org_to_test.get_specific_project(project_id=TEST_PROJECT_ID_SCA)

        if not project_to_test:
            raise unittest.SkipTest(f"Test Project {TEST_PROJECT_ID_SCA} not found in Org {TEST_ORG_ID}.")
        cls.project_to_test = project_to_test

        # Fetch one issue from this project for basic instantiation tests
        cls.issue_from_project = None
        if cls.project_to_test:
            # API for issues endpoint likely requires limit >=10
            issues = cls.project_to_test.fetch_issues(params={'limit': 10}) 
            if issues:
                cls.issue_from_project = issues[0]
        
        # Fetch one issue directly from the org that we know belongs to TEST_PROJECT_ID_SCA
        # This will be used to test lazy loading of the project by the issue
        cls.issue_from_org_for_lazy_load_test = None
        if cls.org_to_test:
            org_issues = cls.org_to_test.fetch_issues(params={
                'scan_item.id': TEST_PROJECT_ID_SCA, 
                'scan_item.type': 'project', 
                'limit': 10 
            })
            if org_issues:
                for issue_in_org in org_issues:
                    if issue_in_org.relationships and \
                       issue_in_org.relationships.scan_item and \
                       issue_in_org.relationships.scan_item.id == TEST_PROJECT_ID_SCA and \
                       issue_in_org.relationships.scan_item.type == 'project':
                        cls.issue_from_org_for_lazy_load_test = issue_in_org
                        cls.api_client.logger.info(
                            f"Selected issue {issue_in_org.id} from org for lazy load test "
                            "as it has the required scan_item relationship."
                        )
                        break
                if not cls.issue_from_org_for_lazy_load_test:
                    cls.api_client.logger.warning(
                        f"No issue found in org {cls.org_to_test.id} (for project {TEST_PROJECT_ID_SCA}) "
                        "with a usable scan_item relationship for lazy load testing."
                    )
        
        if not cls.issue_from_project and not cls.issue_from_org_for_lazy_load_test:
            cls.api_client.logger.warning(f"No issues found for project {TEST_PROJECT_ID_SCA} to conduct issue tests.")


    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'api_client') and cls.api_client:
            cls.api_client.close()

    def setUp(self):
        self.original_loading_strategy = API_CONFIG.get("loading_strategy")
        API_CONFIG["loading_strategy"] = "lazy"

    def tearDown(self):
        API_CONFIG["loading_strategy"] = self.original_loading_strategy

    def test_issue_instantiation_via_project(self):
        """Test IssuePydanticModel instantiation when fetched via a Project."""
        if not self.issue_from_project:
            self.skipTest(f"No issue fetched via project {TEST_PROJECT_ID_SCA} in setUpClass.")
        
        self.assertIsInstance(self.issue_from_project, IssuePydanticModel)
        self.assertIsNotNone(self.issue_from_project.id)
        self.assertIsNotNone(self.issue_from_project.type)
        self.assertIsNotNone(self.issue_from_project.attributes.title)
        
        # Check if context objects were passed correctly
        self.assertIs(self.issue_from_project._api_client, self.api_client)
        self.assertIs(self.issue_from_project._organization, self.org_to_test)
        self.assertIs(self.issue_from_project._project, self.project_to_test)
        self.assertIs(self.issue_from_project._group, self.group)


    def test_lazy_load_issue_project_when_fetched_via_org(self):
        """Test lazy loading of an Issue's project if the issue was fetched at org level."""
        if not self.issue_from_org_for_lazy_load_test:
            self.skipTest(f"No suitable issue fetched via org for project {TEST_PROJECT_ID_SCA} in setUpClass.")

        API_CONFIG["loading_strategy"] = "lazy"
        
        # Ensure the issue was fetched without direct project context initially for this test
        # (The setUpClass fetches it via org, so _project should be None initially if not passed explicitly)
        # Re-fetch to ensure clean state for this specific test's purpose if needed,
        # or rely on setUpClass providing an issue where _project wasn't set.
        # For simplicity, we assume issue_from_org_for_lazy_load_test has _project=None.
        # If from_api_response for Issue always sets _project if project_id is in relationships,
        # this test needs adjustment or a mock.
        # Let's assume from_api_response for Issue does NOT auto-set _project from relationships.
        
        
        test_issue = self.issue_from_org_for_lazy_load_test
        
        # Manually ensure _project is None to simulate it hasn't been loaded yet.
        # This is valid because when IssuePydanticModel.from_api_response is called by
        # OrganizationPydanticModel.fetch_issues, the 'project' argument is None.
        test_issue._project = None 

        self.assertIsNone(test_issue._project, "Issue's _project should be None before lazy loading to test property access.")
        
        # Access the .project property to trigger lazy loading
        loaded_project = test_issue.project
        
        self.assertIsNotNone(loaded_project, "Project should be loaded after accessing .project property.")
        if loaded_project is None: # Add this check to satisfy Pylance and for robustness
            self.fail("loaded_project is None after accessing test_issue.project property.") 
            return # Should not be reached if assertIsNotNone works, but good for type checker

        self.assertIsInstance(loaded_project, ProjectPydanticModel)
        
        # Verify the loaded project's ID
        expected_project_id = None
        if test_issue.relationships and test_issue.relationships.scan_item and \
           test_issue.relationships.scan_item.type == 'project':
            expected_project_id = test_issue.relationships.scan_item.id
        
        self.assertIsNotNone(expected_project_id, "Issue relationship data does not contain project ID.")
        self.assertEqual(loaded_project.id, expected_project_id)
        self.assertEqual(loaded_project.id, TEST_PROJECT_ID_SCA) # Also check against known ID

        # Check if the parent organization of the loaded project is correct
        self.assertIs(loaded_project._organization, self.org_to_test)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s-%(levelname)s-%(name)s - %(message)s')
    unittest.main()
