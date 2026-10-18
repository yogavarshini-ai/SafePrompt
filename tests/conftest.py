import sys, os
from pathlib import Path
import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.append(project_root)

from backend.auth_service import get_auth_service


@pytest.fixture
def auth_headers_employee():
    token = get_auth_service().create_access_token(
        user_id="u-emp-fixture",
        username="employee_user",
        role="employee",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers_hr():
    token = get_auth_service().create_access_token(
        user_id="u-hr-fixture",
        username="hr_specialist",
        role="hr",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers_admin():
    token = get_auth_service().create_access_token(
        user_id="u-admin-fixture",
        username="admin",
        role="admin",
    )
    return {"Authorization": f"Bearer {token}"}
