import 'package:campusshield_app/api.dart';
import 'package:campusshield_app/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('normalizeBaseUrl', () {
    test('keeps empty as same-origin', () {
      expect(normalizeBaseUrl('  '), '');
    });

    test('adds a scheme and strips trailing slashes', () {
      expect(normalizeBaseUrl('127.0.0.1:3999///'), 'http://127.0.0.1:3999');
    });

    test('keeps https URLs', () {
      expect(normalizeBaseUrl('https://shield.example.edu'), 'https://shield.example.edu');
    });

    test('rejects unsupported schemes', () {
      expect(() => normalizeBaseUrl('ftp://shield.example.edu'), throwsA(isA<ApiException>()));
    });
  });

  test('parses a protection payload', () {
    final data = ProtectionData.fromJson({
      'devices': [
        {
          'id': 'local-host',
          'name': 'Lab Mac',
          'kind': 'computer',
          'platformLabel': 'macOS 15.6',
          'role': 'host',
          'score': 90,
          'grade': 'Good',
          'checks': [
            {'id': 'firewall', 'title': 'Firewall', 'status': 'fail', 'detail': 'Off'}
          ]
        }
      ],
      'summary': {'total': 1, 'checked': 1, 'average': 90, 'grade': 'Good'},
      'scanner': {
        'available': true,
        'signatureVersion': '2026.11-test',
        'signatureCount': 1,
        'preferences': {
          'realtime': true,
          'notify': false,
          'exclusions': ['/tmp/vendor'],
          'schedule': {'enabled': true, 'scope': 'full', 'frequency': 'weekly', 'weekday': 3, 'time': '07:30'}
        },
        'watch': {'enabled': true},
      },
      'scans': [
        {
          'id': 'scan-1',
          'scope': 'custom',
          'status': 'complete',
          'filesScanned': 2,
          'threats': [
            {
              'id': 'threat-1',
              'name': 'install.sh',
              'severity': 'high',
              'status': 'detected',
              'reasons': [
                {'id': 'download-execute', 'label': 'Downloads and runs code'}
              ]
            }
          ]
        }
      ],
      'quarantine': []
    });

    expect(data.devices, hasLength(1));
    expect(data.devices.first.checks.first.title, 'Firewall');
    expect(data.summary.average, 90);
    expect(data.scanner.preferences.realtime, isTrue);
    expect(data.scanner.preferences.schedule.frequency, 'weekly');
    expect(data.scanner.watch.enabled, isTrue);
    expect(data.openThreats, hasLength(1));
    expect(data.openThreats.first.reasons.first.label, 'Downloads and runs code');
  });

  test('round-trips preferences to the API body', () {
    const prefs = Preferences(
      realtime: true,
      notify: true,
      exclusions: ['/tmp/vendor'],
      schedule: Schedule(
        enabled: true,
        scope: 'quick',
        frequency: 'daily',
        weekday: 1,
        time: '09:00',
      ),
    );

    final body = prefs.toJson();
    expect(body['realtime'], isTrue);
    expect(body['exclusions'], ['/tmp/vendor']);
    expect((body['schedule'] as Map)['time'], '09:00');
  });

  test('parses AI config from storage safely', () {
    final config = AiConfig.fromStorage('{"baseUrl":"https://api.example.com/v1","model":"m1","apiKey":"k"}');
    expect(config.isConfigured, isTrue);
    expect(config.model, 'm1');

    expect(AiConfig.fromStorage('not-json').isConfigured, isFalse);
  });
}
