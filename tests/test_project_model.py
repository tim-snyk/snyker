import unittest
import os
import logging

from snyker import (
    GroupPydanticModel,
    OrganizationPydanticModel,
    ProjectPydanticModel,
    IssuePydanticModel,
    APIClient,
)
from snyker.config import API_CONFIG

# Provided IDs
TEST_GROUP_ID = "9365faba-3e72-4fda-9974-267779137aa6"
TEST_ORG_ID = "8c12aada-dec1-4670-a39e-60fc1ec59e55"  # Team G


@unittest.skipIf(
    not os.getenv("SNYK_TOKEN"), "SNYK_TOKEN not set, skipping integration tests"
)
class TestProjectPydanticModelIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api_client = APIClient(logging_level=logging.DEBUG)
        API_CONFIG["loading_strategy"] = "lazy"  # Ensure lazy for setup

        try:
            group = GroupPydanticModel.get_instance(
                api_client=cls.api_client, group_id=TEST_GROUP_ID
            )
        except ValueError as e:
            raise unittest.SkipTest(
                f"Could not get group instance {TEST_GROUP_ID}: {e}"
            )

        org_to_test = None
        if group:
            orgs = group.organizations  # Property access, respects lazy
            for org_instance in orgs:
                if org_instance.id == TEST_ORG_ID:
                    org_to_test = org_instance
                    break

        if not org_to_test:
            raise unittest.SkipTest(
                f"Test Organization {TEST_ORG_ID} not found in Group {TEST_GROUP_ID}."
            )

        cls.org_to_test = org_to_test  # Assign to class attribute

        projects_by_type = {}
        if cls.org_to_test:
            projects = cls.org_to_test.projects  # Property access, respects lazy
            for proj_instance in projects:
                if proj_instance.project_type not in projects_by_type:
                    projects_by_type[proj_instance.project_type] = proj_instance

        cls.projects_by_type = projects_by_type

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "api_client") and cls.api_client:
            cls.api_client.close()

    def setUp(self):
        self.original_loading_strategy = API_CONFIG.get("loading_strategy")
        API_CONFIG["loading_strategy"] = "lazy"  # Default to lazy for most tests

    def tearDown(self):
        API_CONFIG["loading_strategy"] = self.original_loading_strategy

    def test_fetch_issues_for_each_project_type(self):
        """Test fetching issues for one project of each type."""
        if not self.projects_by_type:
            self.skipTest("No projects found to test.")

        for project_type, project in self.projects_by_type.items():
            with self.subTest(project_type=project_type):
                self.api_client.logger.info(
                    f"Testing project: {project.name} ({project.id})"
                )
                issues = project.fetch_issues()
                self.assertIsNotNone(issues)
                self.assertIsInstance(issues, list)
                if issues:
                    self.assertIsInstance(issues[0], IssuePydanticModel)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s-%(levelname)s-%(name)s - %(message)s"
    )
    unittest.main()
