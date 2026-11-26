REPO = 'trufflehog'
TARGETS = {
    ('entropy-secret', 'fixture_filename'): (
        'cmd/analyzer/customdetectors/entropy_proximity.go', 'cmd/analyzer/dlp_enhancer_fixture_filename_test.go'),
}
TEST_API = ('Use package main. Drive newScanner().scan(context.Background(), []byte(text), 0.75) '
            'and assert the relevant EntityType. Keep existing true detections.')
