import 'dart:async';
import 'dart:convert';

import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'api.dart';
import 'models.dart';

const _apiBaseKey = 'campusshield.apiBase';
const _apiTokenKey = 'campusshield.apiToken';
const _sessionKey = 'campusshield.session';
const _aiKey = 'campusshield.ai';

class AppState extends ChangeNotifier {
  AppState({ApiClient? api}) : api = api ?? ApiClient();

  final ApiClient api;

  bool booting = true;
  bool refreshing = false;
  bool checkingAuth = false;
  String? error;
  ProtectionData? protection;
  OverviewSummary overview = OverviewSummary.empty;
  List<ActivityEntry> activity = [];
  AiConfig ai = const AiConfig(baseUrl: '', model: '', apiKey: '');
  String apiBase = '';
  String apiToken = '';
  String sessionToken = '';
  AuthUser? user;
  AuthStatus authStatus = AuthStatus.unknown;
  String? alertMessage;

  Timer? _timer;
  bool _wasRunning = false;
  bool _seededThreats = false;
  Set<String> _knownOpenThreats = {};

  bool get signedIn => user != null;
  bool get signupOpen => authStatus.signupOpen;

  ProtectionSummary get score => protection?.summary ?? ProtectionSummary.empty;
  ScannerStatus get scanner => protection?.scanner ?? ScannerStatus.empty;
  List<ScanRecord> get scans => protection?.scans ?? const [];
  List<Threat> get openThreats => protection?.openThreats ?? const [];
  List<QuarantineEntry> get quarantine => protection?.quarantine ?? const [];
  List<Device> get devices => protection?.devices ?? const [];
  ScanRecord? get activeScan => scanner.active;
  bool get hasServer => error == null && protection != null;

  Future<void> init() async {
    final store = await SharedPreferences.getInstance();
    apiBase = store.getString(_apiBaseKey) ?? '';
    apiToken = store.getString(_apiTokenKey) ?? '';
    sessionToken = store.getString(_sessionKey) ?? '';
    ai = AiConfig.fromStorage(store.getString(_aiKey));
    api.configure(baseUrl: apiBase, token: apiToken, session: sessionToken);
    await checkAuth();
    booting = false;
    _timer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (!booting) refresh(silent: true);
    });
    notifyListeners();
  }

  // Asks the server who we are. The status route stays reachable without a
  // session so the app can choose between signup, sign-in, and the dashboard.
  Future<void> checkAuth() async {
    checkingAuth = true;
    notifyListeners();

    try {
      final status = await api.authStatus();
      authStatus = status;

      if (status.user == null) {
        if (sessionToken.isNotEmpty) await _clearSession();
        user = null;
        protection = null;
        error = null;
      } else {
        user = status.user;
        await refresh();
      }
    } catch (caught) {
      error = caught is ApiException
          ? caught.message
          : 'Could not reach the CampusShield server. Check the server address.';
    } finally {
      checkingAuth = false;
      notifyListeners();
    }
  }

  Future<void> createAccount({
    required String name,
    required String email,
    required String password,
    required String baseUrl,
  }) async {
    await _setBaseUrl(baseUrl);
    final session = await api.signup(name: name, email: email, password: password);
    await _applySession(session);
  }

  Future<void> signIn({
    required String email,
    required String password,
    required String baseUrl,
  }) async {
    await _setBaseUrl(baseUrl);
    final session = await api.login(email: email, password: password);
    await _applySession(session);
  }

  Future<void> signOut() async {
    try {
      if (sessionToken.isNotEmpty) await api.logout();
    } catch (_) {
      /* the local session is cleared either way */
    }

    await _clearSession();
    authStatus = const AuthStatus(hasAccount: true, signupOpen: false);
    notifyListeners();
  }

  Future<void> _applySession(AuthSession session) async {
    user = session.user;
    sessionToken = session.token;
    authStatus = AuthStatus(hasAccount: true, signupOpen: false, user: session.user);
    api.configure(baseUrl: apiBase, token: apiToken, session: sessionToken);

    final store = await SharedPreferences.getInstance();
    await store.setString(_sessionKey, sessionToken);

    error = null;
    await refresh();
    notifyListeners();
  }

  Future<void> _clearSession() async {
    sessionToken = '';
    user = null;
    protection = null;
    overview = OverviewSummary.empty;
    activity = [];
    error = null;
    api.configure(baseUrl: apiBase, token: apiToken, session: '');

    final store = await SharedPreferences.getInstance();
    await store.remove(_sessionKey);
  }

  Future<void> _setBaseUrl(String baseUrl) async {
    final clean = normalizeBaseUrl(baseUrl);
    apiBase = clean;
    api.configure(baseUrl: apiBase, token: apiToken, session: sessionToken);

    final store = await SharedPreferences.getInstance();
    if (clean.isEmpty) {
      await store.remove(_apiBaseKey);
    } else {
      await store.setString(_apiBaseKey, clean);
    }
  }

  Future<void> refresh({bool silent = false}) async {
    if (user == null || refreshing) return;
    refreshing = true;
    if (!silent) {
      error = null;
      notifyListeners();
    }

    try {
      final results = await Future.wait<Object>([
        api.protection(),
        api.summary(),
        api.activity(limit: 40),
      ]);

      protection = results[0] as ProtectionData;
      overview = results[1] as OverviewSummary;
      activity = results[2] as List<ActivityEntry>;
      error = null;
      _checkNewThreats();
    } catch (caught) {
      if (caught is ApiException && caught.isAuthRequired) {
        await _clearSession();
        authStatus = const AuthStatus(hasAccount: true, signupOpen: false);
      } else {
        error = caught is ApiException
            ? caught.message
            : 'Could not load CampusShield data. Check that the server is running.';
        if (!silent) protection = null;
      }
    } finally {
      refreshing = false;
      _schedulePolling();
      notifyListeners();
    }
  }

  void _schedulePolling() {
    if (protection?.scanner.active != null && !_wasRunning) {
      _wasRunning = true;
      Timer.periodic(const Duration(milliseconds: 1500), (timer) async {
        final active = protection?.scanner.active;
        if (active == null) {
          timer.cancel();
          _wasRunning = false;
          await refresh(silent: true);
          return;
        }
        await refresh(silent: true);
      });
    }
  }

  void _checkNewThreats() {
    if (!scanner.preferences.notify) {
      _knownOpenThreats = openThreats.map((threat) => threat.id).toSet();
      return;
    }

    final current = openThreats.map((threat) => threat.id).toSet();

    if (!_seededThreats) {
      _seededThreats = true;
      _knownOpenThreats = current;
      return;
    }

    final fresh = current.difference(_knownOpenThreats);
    _knownOpenThreats = current;

    if (fresh.isEmpty) return;
    final first = openThreats.firstWhere((threat) => fresh.contains(threat.id));
    alertMessage = fresh.length == 1
        ? 'New finding: ${first.name} (${first.severity}).'
        : '${fresh.length} new findings were detected.';
    notifyListeners();
  }

  String? takeAlert() {
    final message = alertMessage;
    alertMessage = null;
    return message;
  }

  Future<void> saveConnection({required String baseUrl, required String token}) async {
    await _setBaseUrl(baseUrl);
    apiToken = token.trim();
    api.configure(baseUrl: apiBase, token: apiToken, session: sessionToken);

    final store = await SharedPreferences.getInstance();
    if (apiToken.isEmpty) {
      await store.remove(_apiTokenKey);
    } else {
      await store.setString(_apiTokenKey, apiToken);
    }

    await checkAuth();
  }

  Future<void> saveAi(AiConfig config) async {
    ai = config;
    final store = await SharedPreferences.getInstance();
    if (!config.isConfigured) {
      await store.remove(_aiKey);
    } else {
      await store.setString(_aiKey, jsonEncode(config.toJson()));
    }
    notifyListeners();
  }

  Future<void> runScan(String scope, {String? path}) async {
    await api.startScan(scope, path: path);
    await refresh();
  }

  Future<void> cancelScan(String id) async {
    await api.cancelScan(id);
    await refresh();
  }

  Future<void> quarantineThreat(Threat threat) async {
    final scanId = _scanIdFor(threat);
    if (scanId == null) throw const ApiException('This finding is not attached to a scan.');
    await api.quarantineThreat(scanId, threat.id);
    await refresh();
  }

  Future<void> quarantineById(String scanId, String threatId) async {
    await api.quarantineThreat(scanId, threatId);
    await refresh();
  }

  Future<void> deleteThreat(Threat threat) async {
    final scanId = _scanIdFor(threat);
    if (scanId == null) throw const ApiException('This finding is not attached to a scan.');
    await api.deleteThreat(scanId, threat.id);
    await refresh();
  }

  String? _scanIdFor(Threat threat) {
    for (final scan in scans) {
      if (scan.threats.any((item) => item.id == threat.id)) return scan.id;
    }
    return null;
  }

  Future<void> restoreQuarantine(QuarantineEntry entry) async {
    await api.restoreQuarantine(entry.id);
    await refresh();
  }

  Future<void> deleteQuarantine(QuarantineEntry entry) async {
    await api.deleteQuarantine(entry.id);
    await refresh();
  }

  Future<void> checkDevice() async {
    await api.checkDevice();
    await refresh();
  }

  Future<void> addDevice({required String name, required String kind, required String platform}) async {
    await api.addDevice(name: name, kind: kind, platform: platform);
    await refresh();
  }

  Future<void> removeDevice(String id) async {
    await api.removeDevice(id);
    await refresh();
  }

  Future<Preferences> savePreferences(Preferences preferences) async {
    final saved = await api.savePreferences(preferences);
    await refresh();
    return saved;
  }

  Future<String> updateSignatures() async {
    final result = await api.updateSignatures();
    await refresh();
    final added = result['added'];
    final version = result['version'];
    if (added is num && added > 0) {
      return 'Signatures updated: $added new hashes (${version ?? 'new version'}).';
    }
    return 'Signatures are up to date${version != null ? ' ($version)' : ''}.';
  }

  Future<String> testAi() async {
    if (!ai.isConfigured) throw const ApiException('Connect an AI endpoint in Settings first.');
    return api.testAi(ai);
  }

  Future<String> explain(Threat threat) async {
    if (!ai.isConfigured) throw const ApiException('Connect an AI endpoint in Settings first.');
    final scanId = _scanIdFor(threat);
    if (scanId == null) throw const ApiException('This finding is not attached to a scan.');
    return api.explainThreat(ai, scanId, threat.id);
  }

  Future<String> summarize() async {
    if (!ai.isConfigured) throw const ApiException('Connect an AI endpoint in Settings first.');
    return api.summarize(ai);
  }

  Future<AssistantSuggestion> assistantSuggestions() =>
      api.assistantSuggestions(ai: ai.isConfigured ? ai : null);

  Future<AssistantReply> askAssistant(
    String message, {
    List<Map<String, String>> history = const [],
  }) =>
      api.assistantChat(
        message: message,
        history: history,
        ai: ai.isConfigured ? ai : null,
      );

  // Device check plus quick scan, both real. The scan keeps running; polling
  // updates the dashboard while the assistant screen watches activeScan.
  Future<AssistantTestResult> runSecurityTest() async {
    final result = await api.securityTest();
    await refresh();
    return result;
  }

  Future<String> assistantRunSummary() =>
      api.assistantRunSummary(ai: ai.isConfigured ? ai : null);

  Future<void> clearAllData() async {
    await api.clearAllData();
    await refresh();
  }

  @override
  void dispose() {
    _timer?.cancel();
    api.close();
    super.dispose();
  }
}
