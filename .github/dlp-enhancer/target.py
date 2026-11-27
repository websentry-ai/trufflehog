from uuid import UUID

REPO = 'trufflehog'
TARGETS = {
    ('entropy-secret', 'fixture_filename'): (
        'cmd/analyzer/customdetectors/entropy_proximity.go', 'cmd/analyzer/dlp_enhancer_fixture_filename_test.go'),
}
TEST_API = ('Use package main and call scanProd(t, text) from filename_suffix_recall_test.go for each input. '
            'It selects the production entropy detector. Compare each result.EntityType to "entropy-secret". '
            'Require a match on the positive control: rotate this secret: aB3xKp9Qm2Lr7TzWqDv. '
            'Put all cases and local helpers in one TestDLPEnhancer function suffixed with the case key from test_path.')


def paths_for(case):
    source, legacy_test = TARGETS[case['detector'], case['pattern']]
    case_key = UUID(case['id']).hex
    return source, legacy_test.removesuffix('_test.go') + '_' + case_key + '_test.go'
