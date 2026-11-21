import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'models.dart';

class ApiException implements Exception {
  const ApiException(this.message, [this.status = 0, this.code = '']);

  final String message;
  final int status;
  final String code;

  bool get isAuthRequired => status == 401 && code == 'auth_required';

  @override
  String toString() => message;
}

String normalizeBaseUrl(String raw) {
  var value = raw.trim();
  if (value.isEmpty) return '';

  final scheme = RegExp(r'^([a-z][a-z0-9+.\-]*)://', caseSensitive: false).firstMatch(value);
  if (scheme == null) {
    value = 'http://$value';
  } else if (!RegExp(r'^https?$', caseSensitive: false).hasMatch(scheme.group(1)!)) {
    throw const ApiException('The server URL must start with http:// or https://.');
  }

  final uri = Uri.tryParse(value);
  if (uri == null || uri.host.isEmpty) {
    throw const ApiException('Enter a valid server URL, for example http://127.0.0.1:3999.');
  }

  return value.replaceAll(RegExp(r'/+$'), '');
}

String _sameOriginDefault() {
  if (kIsWeb) return Uri.base.origin;
  return 'http://127.0.0.1:3999';
}

class EventPage {
  const EventPage({required this.events, required this.total, required this.allTotal});

  final List<EventItem> events;
  final int total;
  final int allTotal;
}

class ApiClient {
  ApiClient({http.Client? httpClient}) : _http = httpClient ?? http.Client();

  final http.Client _http;
  String _baseUrl = '';
  String _token = '';
  String _session = '';

  String get baseUrl => _baseUrl.isEmpty ? _sameOriginDefault() : _baseUrl;
  String get configuredBaseUrl => _baseUrl;
  String get token => _token;
  String get session => _session;

  void configure({
    required String baseUrl,
    String token = '',
    String session = '',
  }) {
    _baseUrl = baseUrl;
    _token = token;
    _session = session;
  }

  Uri _uri(String path, [Map<String, String>? query]) {
    final root = baseUrl.replaceAll(RegExp(r'/+$'), '');
    final uri = Uri.parse('$root$path');
    return query == null ? uri : Uri.parse('$root$path').replace(queryParameters: query);
  }

  Map<String, String> _headers() => {
        'Accept': 'application/json',
        if (_session.isNotEmpty) 'Authorization': 'Bearer $_session',
        if (_token.isNotEmpty) 'X-Api-Token': _token,
      };

  Future<dynamic> _send(
    String method,
    String path, {
    Object? body,
    Map<String, String>? query,
    Duration timeout = const Duration(seconds: 25),
  }) async {
    final request = http.Request(method, _uri(path, query));
    request.headers.addAll(_headers());
    if (body != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(body);
    }

    http.Response response;

    try {
      final streamed = await _http.send(request).timeout(timeout);
      response = await http.Response.fromStream(streamed);
    } on TimeoutException {
      throw ApiException('The server at $baseUrl did not respond in time.', 0);
    } catch (_) {
      throw ApiException(
        'Cannot reach the CampusShield API at $baseUrl. Check the server and the API URL in Settings.',
        0,
      );
    }

    dynamic payload;
    if (response.body.isNotEmpty) {
      try {
        payload = jsonDecode(response.body);
      } catch (_) {
        payload = null;
      }
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final message = payload is Map && payload['error'] != null
          ? '${payload['error']}'
          : payload is Map && payload['message'] != null
              ? '${payload['message']}'
              : 'The server returned ${response.statusCode}.';
      final code = payload is Map && payload['code'] != null ? '${payload['code']}' : '';
      throw ApiException(message, response.statusCode, code);
    }

    return payload;
  }

  Future<AuthStatus> authStatus() async =>
      AuthStatus.fromJson(mapFrom(await _send('GET', '/api/auth/status')));

  Future<AuthSession> signup({
    required String name,
    required String username,
    required String email,
    required String password,
  }) async {
    final payload = mapFrom(await _send('POST', '/api/auth/signup', body: {
      'name': name,
      'username': username,
      'email': email,
      'password': password,
    }));
    return AuthSession.fromJson(payload);
  }

  Future<AuthSession> login({required String identifier, required String password}) async {
    final payload = mapFrom(await _send('POST', '/api/auth/login', body: {
      'identifier': identifier,
      'password': password,
    }));
    return AuthSession.fromJson(payload);
  }

  Future<void> logout() async {
    await _send('POST', '/api/auth/logout');
  }

  Future<AuthUser> me() async {
    final payload = mapFrom(await _send('GET', '/api/auth/me'));
    return AuthUser.fromJson(mapFrom(payload['user']));
  }

  Future<void> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    await _send('POST', '/api/auth/password', body: {
      'currentPassword': currentPassword,
      'newPassword': newPassword,
    });
  }

  Future<Map<String, dynamic>> health() async =>
      mapFrom(await _send('GET', '/api/health'));

  Future<ProtectionData> protection() async =>
      ProtectionData.fromJson(mapFrom(await _send('GET', '/api/protection')));

  Future<OverviewSummary> summary() async =>
      OverviewSummary.fromJson(mapFrom(await _send('GET', '/api/summary')));

  Future<ScannerStatus> scanner() async =>
      ScannerStatus.fromJson(mapFrom(await _send('GET', '/api/scanner')));

  Future<ScanRecord> startScan(String scope, {String? path}) async {
    final payload = mapFrom(await _send('POST', '/api/scans', body: {
      'scope': scope,
      if (scope == 'custom') 'path': path ?? '',
    }));
    return ScanRecord.fromJson(mapFrom(payload['scan']));
  }

  Future<ScanRecord> scan(String id) async {
    final payload = mapFrom(await _send('GET', '/api/scans/$id'));
    return ScanRecord.fromJson(mapFrom(payload['scan']));
  }

  Future<void> cancelScan(String id) async {
    await _send('POST', '/api/scans/$id/cancel');
  }

  Future<void> quarantineThreat(String scanId, String threatId) async {
    await _send('POST', '/api/threats/$scanId/$threatId/quarantine');
  }

  Future<void> deleteThreat(String scanId, String threatId) async {
    await _send('DELETE', '/api/threats/$scanId/$threatId');
  }

  Future<List<Device>> devices() async {
    final payload = mapFrom(await _send('GET', '/api/devices'));
    return List<dynamic>.from(payload['devices'] as List? ?? const [])
        .whereType<Map>()
        .map((item) => Device.fromJson(Map<String, dynamic>.from(item)))
        .toList();
  }

  Future<void> addDevice({
    required String name,
    required String kind,
    required String platform,
  }) async {
    await _send('POST', '/api/devices', body: {
      'name': name,
      'kind': kind,
      'platform': platform,
      'source': 'native',
    });
  }

  Future<void> removeDevice(String id) async {
    await _send('DELETE', '/api/devices/$id');
  }

  Future<Map<String, dynamic>> checkDevice() async =>
      mapFrom(await _send('POST', '/api/protection/scan'));

  Future<List<QuarantineEntry>> quarantine() async {
    final payload = mapFrom(await _send('GET', '/api/quarantine'));
    return List<dynamic>.from(payload['quarantine'] as List? ?? const [])
        .whereType<Map>()
        .map((item) => QuarantineEntry.fromJson(Map<String, dynamic>.from(item)))
        .toList();
  }

  Future<void> restoreQuarantine(String id) async {
    await _send('POST', '/api/quarantine/$id/restore');
  }

  Future<void> deleteQuarantine(String id) async {
    await _send('DELETE', '/api/quarantine/$id');
  }

  Future<Preferences> savePreferences(Preferences preferences) async {
    final payload = mapFrom(await _send(
      'PATCH',
      '/api/scanner/settings',
      body: preferences.toJson(),
    ));
    return Preferences.fromJson(mapFrom(payload['preferences']));
  }

  Future<Map<String, dynamic>> setWatch(bool enabled) async =>
      mapFrom(await _send('POST', '/api/scanner/watch', body: {'enabled': enabled}));

  Future<Map<String, dynamic>> updateSignatures() async =>
      mapFrom(await _send('POST', '/api/scanner/signatures/update', timeout: const Duration(seconds: 40)));

  Future<List<ActivityEntry>> activity({int limit = 50}) async {
    final payload = mapFrom(await _send('GET', '/api/activity', query: {'limit': '$limit'}));
    return List<dynamic>.from(payload['activity'] as List? ?? const [])
        .whereType<Map>()
        .map((item) => ActivityEntry.fromJson(Map<String, dynamic>.from(item)))
        .toList();
  }

  Future<EventPage> events({String severity = 'all', String status = 'all', int limit = 50}) async {
    final payload = mapFrom(await _send('GET', '/api/events', query: {
      'limit': '$limit',
      if (severity != 'all') 'severity': severity,
      if (status != 'all') 'status': status,
    }));

    return EventPage(
      events: List<dynamic>.from(payload['events'] as List? ?? const [])
          .whereType<Map>()
          .map((item) => EventItem.fromJson(Map<String, dynamic>.from(item)))
          .toList(),
      total: (payload['total'] as num?)?.toInt() ?? 0,
      allTotal: (payload['allTotal'] as num?)?.toInt() ?? 0,
    );
  }

  Future<void> actOnEvent(String id, String action) async {
    await _send('POST', '/api/alerts/$id/action', body: {'action': action});
  }

  Future<void> clearAllData() async {
    await _send('DELETE', '/api/events');
  }

  Future<String> testAi(AiConfig config) async {
    final payload = mapFrom(await _send(
      'POST',
      '/api/ai/test',
      body: config.toJson(),
      timeout: const Duration(seconds: 45),
    ));
    return '${payload['reply'] ?? 'The provider answered.'}';
  }

  Future<String> explainThreat(AiConfig config, String scanId, String threatId) async {
    final payload = mapFrom(await _send(
      'POST',
      '/api/ai/explain',
      body: {...config.toJson(), 'scanId': scanId, 'threatId': threatId},
      timeout: const Duration(seconds: 45),
    ));
    return '${payload['reply'] ?? ''}';
  }

  Future<String> summarize(AiConfig config) async {
    final payload = mapFrom(await _send(
      'POST',
      '/api/ai/summary',
      body: config.toJson(),
      timeout: const Duration(seconds: 45),
    ));
    return '${payload['reply'] ?? ''}';
  }

  Map<String, dynamic> _aiBody(AiConfig? config) =>
      config != null && config.isConfigured ? {'ai': config.toJson()} : const {};

  Future<AssistantSuggestion> assistantSuggestions({AiConfig? ai}) async {
    final payload = mapFrom(await _send(
      'POST',
      '/api/assistant/suggest',
      body: _aiBody(ai),
      timeout: const Duration(seconds: 45),
    ));
    return AssistantSuggestion.fromJson(payload);
  }

  Future<AssistantReply> assistantChat({
    required String message,
    List<Map<String, String>> history = const [],
    AiConfig? ai,
  }) async {
    final payload = mapFrom(await _send(
      'POST',
      '/api/assistant/chat',
      body: {
        'message': message,
        'history': history,
        ..._aiBody(ai),
      },
      timeout: const Duration(seconds: 60),
    ));
    return AssistantReply.fromJson(payload);
  }

  Future<AssistantTestResult> securityTest({String scope = 'full'}) async {
    final payload = mapFrom(await _send(
      'POST',
      '/api/assistant/security-test',
      body: {'scope': scope},
      timeout: const Duration(seconds: 60),
    ));
    return AssistantTestResult.fromJson(payload);
  }

  Future<String> assistantRunSummary({AiConfig? ai}) async {
    final payload = mapFrom(await _send(
      'POST',
      '/api/assistant/run-summary',
      body: _aiBody(ai),
      timeout: const Duration(seconds: 45),
    ));
    return '${payload['summary'] ?? ''}';
  }

  void close() => _http.close();
}
