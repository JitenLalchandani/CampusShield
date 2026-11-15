import 'dart:async';
import 'dart:convert';

import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'api.dart';
import 'models.dart';

const _apiBaseKey = 'campusshield.apiBase';
const _apiTokenKey = 'campusshield.apiToken';
const _aiKey = 'campusshield.ai';

class AppState extends ChangeNotifier {
  AppState({ApiClient? api}) : api = api ?? ApiClient();

  final ApiClient api;

  bool booting = true;
  bool refreshing = false;
  String? error;
  ProtectionData? protection;
  OverviewSummary overview = OverviewSummary.empty;
  List<ActivityEntry> activity = [];
  AiConfig ai = const AiConfig(baseUrl: '', model: '', apiKey: '');
  String apiBase = '';
  String apiToken = '';
  String? alertMessage;

  Timer? _timer;
  bool _wasRunning = false;
  bool _seededThreats = false;
  Set<String> _knownOpenThreats = {};

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
    ai = AiConfig.fromStorage(store.getString(_aiKey));
    api.configure(baseUrl: apiBase, token: apiToken);
    await refresh();
    booting = false;
    _timer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (!booting) refresh(silent: true);
    });
    notifyListeners();
  }

  Future<void> refresh({bool silent = false}) async {
    if (refreshing) return;
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
      error = caught is ApiException
          ? caught.message
          : 'Could not load CampusShield data. Check that the server is running.';
      if (!silent) protection = null;
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
    final cleanBase = normalizeBaseUrl(baseUrl);
    apiBase = cleanBase;
    apiToken = token.trim();
    api.configure(baseUrl: apiBase, token: apiToken);

    final store = await SharedPreferences.getInstance();
    if (cleanBase.isEmpty) {
      await store.remove(_apiBaseKey);
    } else {
      await store.setString(_apiBaseKey, cleanBase);
    }
    if (apiToken.isEmpty) {
      await store.remove(_apiTokenKey);
    } else {
      await store.setString(_apiTokenKey, apiToken);
    }

    await refresh();
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
