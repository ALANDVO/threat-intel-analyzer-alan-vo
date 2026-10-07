"""Pytest fixtures for threat intel analyzer backend test suite."""
import os
import pytest
from datetime import datetime, timedelta, timezone
from starlette.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Force test configuration
os.environ["ENVIRONMENT"] = "test"
os.environ["DEMO_MODE"] = "true"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from app.core.config import settings
settings.ENVIRONMENT = "test"
settings.DEMO_MODE = True
settings.DATABASE_URL = "sqlite:///:memory:"

from app.core.database import Base, get_db
from app.core.security import generate_csrf_token, generate_session_token
from app.models.entities import AssetEntity, SessionEntity, UserEntity, VulnerabilityEntity, utc_now
from app.main import create_app

# In-memory SQLite engine for tests
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    app = create_app()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def users(db_session):
    """Creates test users for viewer, analyst, and admin roles."""
    viewer = UserEntity(
        id="user-viewer-1",
        email="viewer@test.local",
        username="test_viewer",
        full_name="Test Viewer",
        role="viewer",
        is_active=True
    )
    analyst = UserEntity(
        id="user-analyst-1",
        email="analyst@test.local",
        username="test_analyst",
        full_name="Test Analyst",
        role="analyst",
        is_active=True
    )
    admin = UserEntity(
        id="user-admin-1",
        email="admin@test.local",
        username="test_admin",
        full_name="Test Admin",
        role="admin",
        is_active=True
    )
    db_session.add_all([viewer, analyst, admin])
    db_session.commit()
    return {"viewer": viewer, "analyst": analyst, "admin": admin}


@pytest.fixture
def auth_headers_and_cookies(db_session, users):
    """Provides authenticated session cookies and CSRF headers for each role."""
    creds = {}
    for role, user in users.items():
        session_id = f"sess-{role}-{generate_session_token()[:16]}"
        csrf_token = f"csrf-{role}-{generate_csrf_token()[:16]}"
        session_rec = SessionEntity(
            id=session_id,
            user_id=user.id,
            csrf_token=csrf_token,
            expires_at=utc_now() + timedelta(hours=2)
        )
        db_session.add(session_rec)
        creds[role] = {
            "cookies": {settings.SESSION_COOKIE_NAME: session_id, settings.CSRF_COOKIE_NAME: csrf_token},
            "headers": {"X-CSRF-Token": csrf_token},
            "user": user,
            "session_id": session_id,
            "csrf_token": csrf_token
        }
    db_session.commit()
    return creds
