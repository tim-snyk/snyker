import unittest
import os
import logging

# Models to be tested or used in tests
from snyker import (
    GroupPydanticModel,
    OrganizationPydanticModel,
    APIClient,
    IssuePydanticModel,
)
from snyker.config import API_CONFIG  # To potentially modify loading_strategy for tests

# Provided IDs
TEST_GROUP_ID = "9365faba-3e72-4fda-9974-267779137aa6"
TEST_ORG_ID = "8c12aada-dec1-4670-a39e-60fc1ec59e55"
# It's good practice to ensure SNYK_TOKEN is set for these tests
# We can add a skip decorator if SNYK_TOKEN is not set.


@unittest.skipIf(
    not os.getenv("SNYK_TOKEN"), "SNYK_TOKEN not set, skipping integration tests"
)
class TestGroupPydanticModelIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api_client = APIClient(logging_level=logging.DEBUG)
        API_CONFIG["loading_strategy"] = "lazy"

        try:
            cls.group = GroupPydanticModel.get_instance(
                api_client=cls.api_client, group_id=TEST_GROUP_ID
            )
        except ValueError as e:
            raise unittest.SkipTest(
                f"Could not get group instance {TEST_GROUP_ID}: {e}"
            )

        org_to_test = None
        if cls.group:
            orgs = cls.group.organizations
            for org_instance in orgs:
                if org_instance.id == TEST_ORG_ID:
                    org_to_test = org_instance
                    break

        if not org_to_test:
            raise unittest.SkipTest(
                f"Test Organization {TEST_ORG_ID} not found in Group {TEST_GROUP_ID}."
            )

        cls.org_to_test = org_to_test

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "api_client") and cls.api_client:
            cls.api_client.close()

    def test_fetch_issues_for_one_project_per_type(self):
        """Test fetching issues for one project of each type in the test org."""
        if not self.org_to_test:
            self.skipTest("Organization to test was not loaded in setUpClass.")

        projects = self.org_to_test.projects
        if not projects:
            self.skipTest(f"No projects found in organization {self.org_to_test.id}.")

        projects_by_type = {}
        for project in projects:
            if project.project_type not in projects_by_type:
                projects_by_type[project.project_type] = project

        for project_type, project in projects_by_type.items():
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
        level=logging.INFO, format="%(asctime)s-%(levelname)s-%(name)s - %(message)s"
    )
    unittest.main()
