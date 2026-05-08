import json, os, sys, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import parse_fingerprint, hash_fingerprint, load_fingerprints, save_fingerprints, calculate_uniqueness, FINGERPRINT_ATTRIBUTES, app

def make_payload(**overrides):
    base = {"user_agent": "Chrome", "language": "en-GB", "platform": "Win32",
            "screen_resolution": "1920x1080", "color_depth": "24",
            "timezone": "Europe/London", "hardware_concurrency": "8",
            "pixel_ratio": "1", "touch_points": "0", "canvas_hash": "abc123"}
    base.update(overrides)
    return base

# =============================================================================
# UNIT TESTS
# Test each function in isolation — no Flask server running.
# Follows the Arrange-Act-Assert pattern (jpreese, n.d.).
# =============================================================================

class TestParseFingerprint:
    """Unit tests for parse_fingerprint() — input validation and sanitisation."""

    def test_valid_payload_returns_expected_keys(self):
        result = parse_fingerprint(make_payload())
        assert set(result.keys()) == set(FINGERPRINT_ATTRIBUTES)

    def test_missing_fields_default_to_unknown(self):
        result = parse_fingerprint({})
        assert all(v == "unknown" for v in result.values())

    def test_extra_keys_discarded(self):
        data = make_payload()
        data["injected"] = "<script>alert('xss')</script>"
        assert "injected" not in parse_fingerprint(data)

    def test_numbers_coerced_to_strings(self):
        result = parse_fingerprint(make_payload(color_depth=24))
        assert result["color_depth"] == "24"

    def test_non_dict_raises_type_error(self):
        with pytest.raises(TypeError):
            parse_fingerprint(["not", "a", "dict"])

    def test_none_raises_type_error(self):
        with pytest.raises(TypeError):
            parse_fingerprint(None)

class TestHashFingerprint:
    """Unit tests for hash_fingerprint() — SHA-256 determinism and format."""

    def test_identical_inputs_same_hash(self):
        a = parse_fingerprint(make_payload())
        assert hash_fingerprint(a) == hash_fingerprint(a)

    def test_different_inputs_different_hash(self):
        a = parse_fingerprint(make_payload(user_agent="Chrome"))
        b = parse_fingerprint(make_payload(user_agent="Firefox"))
        assert hash_fingerprint(a) != hash_fingerprint(b)

    def test_output_is_64_char_hex(self):
        h = hash_fingerprint(parse_fingerprint(make_payload()))
        assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)

    def test_key_order_does_not_affect_hash(self):
        assert hash_fingerprint({"a": "1", "b": "2"}) == hash_fingerprint({"b": "2", "a": "1"})

    def test_single_char_change_changes_hash(self):
        a = parse_fingerprint(make_payload(canvas_hash="abc123"))
        b = parse_fingerprint(make_payload(canvas_hash="abc124"))
        assert hash_fingerprint(a) != hash_fingerprint(b)

class TestLoadFingerprints:
    """Unit tests for load_fingerprints() — file I/O and error resilience."""

    def test_missing_file_returns_empty_list(self, tmp_path):
        assert load_fingerprints(str(tmp_path / "none.json")) == []

    def test_valid_file_loads_correctly(self, tmp_path):
        fp = str(tmp_path / "fp.json")
        with open(fp, "w") as f: json.dump([{"hash": "abc"}], f)
        assert load_fingerprints(fp) == [{"hash": "abc"}]

    def test_malformed_json_returns_empty_list(self, tmp_path):
        fp = str(tmp_path / "bad.json")
        with open(fp, "w") as f: f.write("{bad json}")
        assert load_fingerprints(fp) == []

    def test_dict_instead_of_list_returns_empty(self, tmp_path):
        fp = str(tmp_path / "wrong.json")
        with open(fp, "w") as f: json.dump({"not": "a list"}, f)
        assert load_fingerprints(fp) == []

class TestSaveFingerprints:
    """Unit tests for save_fingerprints() — persistence correctness."""

    def test_round_trip(self, tmp_path):
        fp = str(tmp_path / "fp.json")
        data = [{"hash": "xyz"}]
        save_fingerprints(data, fp)
        assert load_fingerprints(fp) == data

    def test_overwrites_existing(self, tmp_path):
        fp = str(tmp_path / "fp.json")
        save_fingerprints([{"hash": "old"}], fp)
        save_fingerprints([{"hash": "new"}], fp)
        assert load_fingerprints(fp)[0]["hash"] == "new"

    def test_creates_file_if_not_exists(self, tmp_path):
        fp = str(tmp_path / "new.json")
        save_fingerprints([], fp)
        assert os.path.exists(fp)

class TestCalculateUniqueness:
    """Unit tests for calculate_uniqueness() — scoring logic."""

    def test_first_submission_is_100_percent(self):
        assert calculate_uniqueness("new", [])["uniqueness_pct"] == 100.0

    def test_matching_count_correct(self):
        stored = [{"hash": "a"}, {"hash": "a"}, {"hash": "b"}]
        assert calculate_uniqueness("a", stored)["matching"] == 2

    def test_unseen_hash_zero_matches(self):
        assert calculate_uniqueness("z", [{"hash": "a"}])["matching"] == 0

    def test_uniqueness_percentage(self):
        stored = [{"hash": "t"}, {"hash": "t"}, {"hash": "o"}, {"hash": "o"}]
        assert calculate_uniqueness("t", stored)["uniqueness_pct"] == 50.0

    def test_unique_hash_deduplication(self):
        stored = [{"hash": "a"}, {"hash": "a"}, {"hash": "b"}]
        assert calculate_uniqueness("a", stored)["unique_hashes"] == 2

    def test_all_keys_present(self):
        r = calculate_uniqueness("a", [{"hash": "a"}])
        assert all(k in r for k in ["total_seen", "matching", "unique_hashes", "uniqueness_pct"])


# =============================================================================
# INTEGRATION TESTS
# Test the Flask routes directly using Flask's built-in test client.
# Verifies that the route handlers, validation, and response codes work
# well  together just.
# =============================================================================

@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Creates a Flask test client with a temporary fingerprint file.
    monkeypatch replaces the FINGERPRINT_FILE constant for each test
    so tests don't interfere with each other or the real data file.
    """
    import app as app_module
    monkeypatch.setattr(app_module, "FINGERPRINT_FILE", str(tmp_path / "test_fp.json"))
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

class TestFingerprintRoute:
    """Integration tests for the POST /fingerprint route."""

    def test_valid_payload_returns_200(self, client):
        response = client.post(
            "/fingerprint",
            data=json.dumps(make_payload()),
            content_type="application/json"
        )
        assert response.status_code == 200

    def test_response_contains_expected_keys(self, client):
        response = client.post(
            "/fingerprint",
            data=json.dumps(make_payload()),
            content_type="application/json"
        )
        data = json.loads(response.data)
        assert "hash" in data
        assert "uniqueness" in data
        assert "attributes" in data

    def test_hash_is_64_characters(self, client):
        response = client.post(
            "/fingerprint",
            data=json.dumps(make_payload()),
            content_type="application/json"
        )
        data = json.loads(response.data)
        assert len(data["hash"]) == 64

    def test_empty_body_returns_400(self, client):
        response = client.post(
            "/fingerprint",
            data="",
            content_type="application/json"
        )
        assert response.status_code == 400

    def test_malformed_json_returns_400(self, client):
        response = client.post(
            "/fingerprint",
            data="{bad json}",
            content_type="application/json"
        )
        assert response.status_code == 400

    def test_second_submission_updates_total(self, client):
        payload = json.dumps(make_payload())
        client.post("/fingerprint", data=payload, content_type="application/json")
        response = client.post("/fingerprint", data=payload, content_type="application/json")
        data = json.loads(response.data)
        assert data["uniqueness"]["total_seen"] >= 1

    def test_different_browsers_get_different_hashes(self, client):
        r1 = client.post("/fingerprint",
            data=json.dumps(make_payload(user_agent="Chrome")),
            content_type="application/json")
        r2 = client.post("/fingerprint",
            data=json.dumps(make_payload(user_agent="Firefox")),
            content_type="application/json")
        assert json.loads(r1.data)["hash"] != json.loads(r2.data)["hash"]


# =============================================================================
# FUNCTIONAL TESTS
# Test the application from the perspective of the end user journey.
# Verifies that the complete workflow produces the expected outcomes,
# treating the application as a black box (Kimla and Czerwinski, 2022).
# =============================================================================

class TestUserJourney:
    """Functional tests — complete end-to-end user workflows."""

    def test_first_visitor_gets_100_percent_unique(self, client):
        """A first-ever submission should always return 100% uniqueness."""
        response = client.post(
            "/fingerprint",
            data=json.dumps(make_payload()),
            content_type="application/json"
        )
        data = json.loads(response.data)
        assert data["uniqueness"]["uniqueness_pct"] == 100.0

    def test_same_browser_twice_reduces_uniqueness(self, client):
    """
    If two different browsers submit, then the first submits again,
    its uniqueness should drop below 100% as it now shares the pool
    with a different fingerprint.
    """
    client.post("/fingerprint",
        data=json.dumps(make_payload(user_agent="BrowserA")),
        content_type="application/json")
    client.post("/fingerprint",
        data=json.dumps(make_payload(user_agent="BrowserB")),
        content_type="application/json")
    response = client.post("/fingerprint",
        data=json.dumps(make_payload(user_agent="BrowserA")),
        content_type="application/json")
    data = json.loads(response.data)
    assert data["uniqueness"]["uniqueness_pct"] < 100.0

    def test_no_pii_in_stored_hash(self, client):
        """
        The returned hash must not contain the raw user agent string.
        Verifies the PII-free storage requirement from the scenario.
        """
        user_agent = "Mozilla/5.0 TestBrowser"
        response = client.post(
            "/fingerprint",
            data=json.dumps(make_payload(user_agent=user_agent)),
            content_type="application/json"
        )
        data = json.loads(response.data)
        assert user_agent not in data["hash"]

    def test_blocked_canvas_still_returns_result(self, client):
        """
        A browser that blocks canvas (privacy extension) sends 'blocked'
        as the canvas_hash. The application should still process it.
        """
        response = client.post(
            "/fingerprint",
            data=json.dumps(make_payload(canvas_hash="blocked")),
            content_type="application/json"
        )
        assert response.status_code == 200

    def test_stats_endpoint_reflects_submissions(self, client):
        """
        After submitting fingerprints, the /stats endpoint should
        reflect the correct total submission count.
        """
        client.post("/fingerprint",
            data=json.dumps(make_payload(user_agent="Browser1")),
            content_type="application/json")
        client.post("/fingerprint",
            data=json.dumps(make_payload(user_agent="Browser2")),
            content_type="application/json")
        response = client.get("/stats")
        data = json.loads(response.data)
        assert data["total_submissions"] == 2
        assert data["unique_fingerprints"] == 2
