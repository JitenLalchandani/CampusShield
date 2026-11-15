import 'dart:convert';

double? _toDouble(dynamic value) =>
    value is num ? value.toDouble() : double.tryParse('$value');

int _toInt(dynamic value, [int fallback = 0]) =>
    value is num ? value.toInt() : int.tryParse('$value') ?? fallback;

String _text(dynamic value, [String fallback = '']) =>
    value == null ? fallback : '$value';

DateTime? _date(dynamic value) =>
    value is String && value.isNotEmpty ? DateTime.tryParse(value)?.toLocal() : null;

Map<String, dynamic> _map(dynamic value) =>
    value is Map ? Map<String, dynamic>.from(value) : <String, dynamic>{};

List<dynamic> _list(dynamic value) => value is List ? value : const [];

Map<String, dynamic> mapFrom(dynamic value) => _map(value);

class DeviceCheck {
  const DeviceCheck({
    required this.id,
    required this.title,
    required this.status,
    required this.severity,
    required this.detail,
    required this.recommendation,
  });

  final String id;
  final String title;
  final String status;
  final String severity;
  final String detail;
  final String recommendation;

  factory DeviceCheck.fromJson(Map<String, dynamic> json) => DeviceCheck(
        id: _text(json['id']),
        title: _text(json['title'], 'Check'),
        status: _text(json['status'], 'unknown'),
        severity: _text(json['severity'], 'info'),
        detail: _text(json['detail']),
        recommendation: _text(json['recommendation']),
      );
}

class Device {
  const Device({
    required this.id,
    required this.name,
    required this.kind,
    required this.platform,
    required this.platformLabel,
    required this.role,
    required this.model,
    required this.score,
    required this.grade,
    required this.checkedAt,
    required this.checks,
  });

  final String id;
  final String name;
  final String kind;
  final String platform;
  final String platformLabel;
  final String role;
  final String model;
  final double? score;
  final String grade;
  final DateTime? checkedAt;
  final List<DeviceCheck> checks;

  bool get isHost => role == 'host';
  bool get isChecked => score != null;

  factory Device.fromJson(Map<String, dynamic> json) => Device(
        id: _text(json['id']),
        name: _text(json['name'], 'Device'),
        kind: _text(json['kind'], 'computer'),
        platform: _text(json['platform']),
        platformLabel: _text(json['platformLabel']),
        role: _text(json['role']),
        model: _text(json['model']),
        score: _toDouble(json['score']),
        grade: _text(json['grade'], 'Not checked'),
        checkedAt: _date(json['checkedAt']),
        checks: _list(json['checks'])
            .whereType<Map>()
            .map((item) => DeviceCheck.fromJson(Map<String, dynamic>.from(item)))
            .toList(),
      );
}

class ProtectionSummary {
  const ProtectionSummary({
    required this.total,
    required this.checked,
    required this.average,
    required this.grade,
    required this.weakestName,
    required this.weakestScore,
  });

  final int total;
  final int checked;
  final double? average;
  final String grade;
  final String? weakestName;
  final double? weakestScore;

  static const empty = ProtectionSummary(
    total: 0,
    checked: 0,
    average: null,
    grade: 'Not checked',
    weakestName: null,
    weakestScore: null,
  );

  factory ProtectionSummary.fromJson(Map<String, dynamic> json) {
    final weakest = _map(json['weakest']);
    return ProtectionSummary(
      total: _toInt(json['total']),
      checked: _toInt(json['checked']),
      average: _toDouble(json['average']),
      grade: _text(json['grade'], 'Not checked'),
      weakestName: weakest.isEmpty ? null : _text(weakest['name']),
      weakestScore: weakest.isEmpty ? null : _toDouble(weakest['score']),
    );
  }
}

class Schedule {
  const Schedule({
    required this.enabled,
    required this.scope,
    required this.frequency,
    required this.weekday,
    required this.time,
    this.lastRunAt,
  });

  final bool enabled;
  final String scope;
  final String frequency;
  final int weekday;
  final String time;
  final DateTime? lastRunAt;

  factory Schedule.fromJson(Map<String, dynamic> json) => Schedule(
        enabled: json['enabled'] == true,
        scope: _text(json['scope'], 'quick'),
        frequency: _text(json['frequency'], 'daily'),
        weekday: _toInt(json['weekday'], 1),
        time: _text(json['time'], '09:00'),
        lastRunAt: _date(json['lastRunAt']),
      );

  Map<String, dynamic> toJson() => {
        'enabled': enabled,
        'scope': scope,
        'frequency': frequency,
        'weekday': weekday,
        'time': time,
      };

  Schedule copyWith({
    bool? enabled,
    String? scope,
    String? frequency,
    int? weekday,
    String? time,
  }) =>
      Schedule(
        enabled: enabled ?? this.enabled,
        scope: scope ?? this.scope,
        frequency: frequency ?? this.frequency,
        weekday: weekday ?? this.weekday,
        time: time ?? this.time,
        lastRunAt: lastRunAt,
      );
}

class Preferences {
  const Preferences({
    required this.realtime,
    required this.notify,
    required this.exclusions,
    required this.schedule,
  });

  final bool realtime;
  final bool notify;
  final List<String> exclusions;
  final Schedule schedule;

  static const defaults = Preferences(
    realtime: false,
    notify: true,
    exclusions: [],
    schedule: Schedule(
      enabled: false,
      scope: 'quick',
      frequency: 'daily',
      weekday: 1,
      time: '09:00',
    ),
  );

  factory Preferences.fromJson(Map<String, dynamic> json) => Preferences(
        realtime: json['realtime'] == true,
        notify: json['notify'] != false,
        exclusions: _list(json['exclusions']).map((item) => '$item').toList(),
        schedule: Schedule.fromJson(_map(json['schedule'])),
      );

  Map<String, dynamic> toJson() => {
        'realtime': realtime,
        'notify': notify,
        'exclusions': exclusions,
        'schedule': schedule.toJson(),
      };
}

class WatchState {
  const WatchState({required this.enabled, required this.roots});

  final bool enabled;
  final List<String> roots;

  factory WatchState.fromJson(Map<String, dynamic> json) => WatchState(
        enabled: json['enabled'] == true,
        roots: _list(json['roots']).map((item) => '$item').toList(),
      );
}

class ScanLimits {
  const ScanLimits({required this.quickFiles, required this.quickMs, required this.fullFiles, required this.fullMs});

  final int quickFiles;
  final int quickMs;
  final int fullFiles;
  final int fullMs;

  factory ScanLimits.fromJson(Map<String, dynamic> json) {
    final quick = _map(json['quick']);
    final full = _map(json['full']);
    return ScanLimits(
      quickFiles: _toInt(quick['maxFiles'], 12000),
      quickMs: _toInt(quick['timeMs'], 180000),
      fullFiles: _toInt(full['maxFiles'], 60000),
      fullMs: _toInt(full['timeMs'], 900000),
    );
  }
}

class ThreatReason {
  const ThreatReason({required this.id, required this.label, required this.weight});

  final String id;
  final String label;
  final int weight;

  factory ThreatReason.fromJson(Map<String, dynamic> json) => ThreatReason(
        id: _text(json['id']),
        label: _text(json['label'], _text(json['id'], 'Suspicious pattern')),
        weight: _toInt(json['weight']),
      );
}

class Threat {
  const Threat({
    required this.id,
    required this.name,
    required this.filePath,
    required this.sha256,
    required this.severity,
    required this.status,
    required this.reasons,
    required this.quarantineId,
  });

  final String id;
  final String name;
  final String filePath;
  final String sha256;
  final String severity;
  final String status;
  final List<ThreatReason> reasons;
  final String? quarantineId;

  bool get isOpen => status == 'detected';

  factory Threat.fromJson(Map<String, dynamic> json) => Threat(
        id: _text(json['id']),
        name: _text(json['name'], 'Unknown file'),
        filePath: _text(json['filePath']),
        sha256: _text(json['sha256']),
        severity: _text(json['severity'], 'low'),
        status: _text(json['status'], 'detected'),
        reasons: _list(json['reasons'])
            .map((item) => item is Map
                ? ThreatReason.fromJson(Map<String, dynamic>.from(item))
                : ThreatReason(id: '$item', label: '$item', weight: 0))
            .toList(),
        quarantineId: json['quarantineId'] == null ? null : _text(json['quarantineId']),
      );
}

class ScanRecord {
  const ScanRecord({
    required this.id,
    required this.scope,
    required this.status,
    required this.startedAt,
    required this.finishedAt,
    required this.filesScanned,
    required this.bytesScanned,
    required this.threatCount,
    required this.threats,
    required this.errors,
    required this.truncated,
    required this.stopReason,
    required this.trigger,
  });

  final String id;
  final String scope;
  final String status;
  final DateTime? startedAt;
  final DateTime? finishedAt;
  final int filesScanned;
  final int bytesScanned;
  final int threatCount;
  final List<Threat> threats;
  final List<ScanError> errors;
  final bool truncated;
  final String? stopReason;
  final String trigger;

  bool get isRunning => status == 'running';
  List<Threat> get openThreats => threats.where((threat) => threat.isOpen).toList();

  factory ScanRecord.fromJson(Map<String, dynamic> json) => ScanRecord(
        id: _text(json['id']),
        scope: _text(json['scope'], 'quick'),
        status: _text(json['status'], 'complete'),
        startedAt: _date(json['startedAt']),
        finishedAt: _date(json['finishedAt']),
        filesScanned: _toInt(json['filesScanned']),
        bytesScanned: _toInt(json['bytesScanned']),
        threatCount: _toInt(json['threatCount'], _list(json['threats']).length),
        threats: _list(json['threats'])
            .whereType<Map>()
            .map((item) => Threat.fromJson(Map<String, dynamic>.from(item)))
            .toList(),
        errors: _list(json['errors'])
            .whereType<Map>()
            .map((item) => ScanError.fromJson(Map<String, dynamic>.from(item)))
            .toList(),
        truncated: json['truncated'] == true,
        stopReason: json['stopReason'] == null ? null : _text(json['stopReason']),
        trigger: _text(json['trigger'], 'manual'),
      );
}

class ScanError {
  const ScanError({required this.path, required this.message});

  final String path;
  final String message;

  factory ScanError.fromJson(Map<String, dynamic> json) => ScanError(
        path: _text(json['path']),
        message: _text(json['message']),
      );
}

class QuarantineEntry {
  const QuarantineEntry({
    required this.id,
    required this.name,
    required this.originalPath,
    required this.severity,
    required this.quarantinedAt,
    required this.sha256,
    required this.reasons,
  });

  final String id;
  final String name;
  final String originalPath;
  final String severity;
  final DateTime? quarantinedAt;
  final String sha256;
  final List<ThreatReason> reasons;

  factory QuarantineEntry.fromJson(Map<String, dynamic> json) => QuarantineEntry(
        id: _text(json['id']),
        name: _text(json['name'], 'Quarantined file'),
        originalPath: _text(json['originalPath']),
        severity: _text(json['severity'], 'low'),
        quarantinedAt: _date(json['quarantinedAt']),
        sha256: _text(json['sha256']),
        reasons: _list(json['reasons'])
            .map((item) => item is Map
                ? ThreatReason.fromJson(Map<String, dynamic>.from(item))
                : ThreatReason(id: '$item', label: '$item', weight: 0))
            .toList(),
      );
}

class ScannerStatus {
  const ScannerStatus({
    required this.available,
    required this.engineVersion,
    required this.signatureVersion,
    required this.signatureCount,
    required this.signatureNote,
    required this.remoteFeedState,
    required this.remoteFeedMessage,
    required this.limits,
    required this.preferences,
    required this.preferencesReady,
    required this.scheduleNextRunAt,
    required this.active,
    required this.watch,
    required this.watchSupported,
  });

  final bool available;
  final String engineVersion;
  final String signatureVersion;
  final int signatureCount;
  final String signatureNote;
  final String remoteFeedState;
  final String? remoteFeedMessage;
  final ScanLimits limits;
  final Preferences preferences;
  final bool preferencesReady;
  final DateTime? scheduleNextRunAt;
  final ScanRecord? active;
  final WatchState watch;
  final bool watchSupported;

  static const empty = ScannerStatus(
    available: false,
    engineVersion: '',
    signatureVersion: '',
    signatureCount: 0,
    signatureNote: '',
    remoteFeedState: 'off',
    remoteFeedMessage: null,
    limits: ScanLimits(quickFiles: 12000, quickMs: 180000, fullFiles: 60000, fullMs: 900000),
    preferences: Preferences.defaults,
    preferencesReady: false,
    scheduleNextRunAt: null,
    active: null,
    watch: WatchState(enabled: false, roots: []),
    watchSupported: false,
  );

  factory ScannerStatus.fromJson(Map<String, dynamic> json) {
    final feed = _map(json['remoteFeed']);
    return ScannerStatus(
      available: json['available'] == true,
      engineVersion: _text(json['engineVersion']),
      signatureVersion: _text(json['signatureVersion']),
      signatureCount: _toInt(json['signatureCount']),
      signatureNote: _text(json['signatureNote']),
      remoteFeedState: _text(feed['state'], 'off'),
      remoteFeedMessage: feed['message'] == null ? null : _text(feed['message']),
      limits: ScanLimits.fromJson(_map(json['limits'])),
      preferences: Preferences.fromJson(_map(json['preferences'])),
      preferencesReady: json['preferencesReady'] == true,
      scheduleNextRunAt: _date(json['scheduleNextRunAt']),
      active: json['active'] is Map
          ? ScanRecord.fromJson(Map<String, dynamic>.from(json['active'] as Map))
          : null,
      watch: WatchState.fromJson(_map(json['watch'])),
      watchSupported: json['watchSupported'] == true,
    );
  }
}

class ProtectionData {
  const ProtectionData({
    required this.devices,
    required this.summary,
    required this.scanner,
    required this.scans,
    required this.quarantine,
    required this.platformLabel,
    required this.storage,
  });

  final List<Device> devices;
  final ProtectionSummary summary;
  final ScannerStatus scanner;
  final List<ScanRecord> scans;
  final List<QuarantineEntry> quarantine;
  final String platformLabel;
  final String storage;

  List<Threat> get openThreats {
    final seen = <String>{};
    final result = <Threat>[];
    for (final scan in scans) {
      for (final threat in scan.threats) {
        if (!threat.isOpen || !seen.add(threat.filePath)) continue;
        result.add(threat);
      }
    }
    return result;
  }

  Device? get host {
    for (final device in devices) {
      if (device.isHost) return device;
    }
    return devices.isEmpty ? null : devices.first;
  }

  factory ProtectionData.fromJson(Map<String, dynamic> json) => ProtectionData(
        devices: _list(json['devices'])
            .whereType<Map>()
            .map((item) => Device.fromJson(Map<String, dynamic>.from(item)))
            .toList(),
        summary: ProtectionSummary.fromJson(_map(json['summary'])),
        scanner: ScannerStatus.fromJson(_map(json['scanner'])),
        scans: _list(json['scans'])
            .whereType<Map>()
            .map((item) => ScanRecord.fromJson(Map<String, dynamic>.from(item)))
            .toList(),
        quarantine: _list(json['quarantine'])
            .whereType<Map>()
            .map((item) => QuarantineEntry.fromJson(Map<String, dynamic>.from(item)))
            .toList(),
        platformLabel: _text(json['platformLabel'], 'Unknown platform'),
        storage: _text(json['storage'], 'Local store'),
      );
}

class ActivityEntry {
  const ActivityEntry({
    required this.id,
    required this.time,
    required this.kind,
    required this.message,
    required this.severity,
  });

  final String id;
  final DateTime? time;
  final String kind;
  final String message;
  final String? severity;

  factory ActivityEntry.fromJson(Map<String, dynamic> json) => ActivityEntry(
        id: _text(json['id']),
        time: _date(json['time']),
        kind: _text(json['kind'], 'activity'),
        message: _text(json['message']),
        severity: json['severity'] == null ? null : _text(json['severity']),
      );
}

class EventItem {
  const EventItem({
    required this.id,
    required this.time,
    required this.type,
    required this.group,
    required this.source,
    required this.count,
    required this.detail,
    required this.severity,
    required this.status,
    required this.rule,
    required this.recommendation,
  });

  final String id;
  final DateTime? time;
  final String type;
  final String group;
  final String source;
  final int count;
  final String detail;
  final String severity;
  final String status;
  final String rule;
  final String recommendation;

  factory EventItem.fromJson(Map<String, dynamic> json) => EventItem(
        id: _text(json['id']),
        time: _date(json['time']),
        type: _text(json['type'], 'event'),
        group: _text(json['group']),
        source: _text(json['source']),
        count: _toInt(json['count']),
        detail: _text(json['detail']),
        severity: _text(json['severity'], 'LOW'),
        status: _text(json['status'], 'Open'),
        rule: _text(json['rule']),
        recommendation: _text(json['recommendation']),
      );
}

class DailyPoint {
  const DailyPoint({required this.label, required this.count});

  final String label;
  final int count;

  factory DailyPoint.fromJson(Map<String, dynamic> json) =>
      DailyPoint(label: _text(json['label']), count: _toInt(json['count']));
}

class OverviewSummary {
  const OverviewSummary({
    required this.average,
    required this.grade,
    required this.checked,
    required this.total,
    required this.eventsTotal,
    required this.highPriority,
    required this.underReview,
    required this.contained,
    required this.open,
    required this.auditTotal,
    required this.daily,
    required this.platformLabel,
    required this.dataSource,
  });

  final double? average;
  final String grade;
  final int checked;
  final int total;
  final int eventsTotal;
  final int highPriority;
  final int underReview;
  final int contained;
  final int open;
  final int auditTotal;
  final List<DailyPoint> daily;
  final String platformLabel;
  final String dataSource;

  static const empty = OverviewSummary(
    average: null,
    grade: 'Not checked',
    checked: 0,
    total: 0,
    eventsTotal: 0,
    highPriority: 0,
    underReview: 0,
    contained: 0,
    open: 0,
    auditTotal: 0,
    daily: [],
    platformLabel: '',
    dataSource: '',
  );

  factory OverviewSummary.fromJson(Map<String, dynamic> json) {
    final protection = _map(json['protection']);
    return OverviewSummary(
      average: _toDouble(protection['average']),
      grade: _text(protection['grade'], 'Not checked'),
      checked: _toInt(protection['checked']),
      total: _toInt(protection['total']),
      eventsTotal: _toInt(json['eventsTotal']),
      highPriority: _toInt(json['highPriority']),
      underReview: _toInt(json['underReview']),
      contained: _toInt(json['contained']),
      open: _toInt(json['open']),
      auditTotal: _toInt(json['auditTotal']),
      daily: _list(json['daily'])
          .whereType<Map>()
          .map((item) => DailyPoint.fromJson(Map<String, dynamic>.from(item)))
          .toList(),
      platformLabel: _text(json['platformLabel']),
      dataSource: _text(json['dataSource']),
    );
  }
}

class AiConfig {
  const AiConfig({required this.baseUrl, required this.model, required this.apiKey});

  final String baseUrl;
  final String model;
  final String apiKey;

  bool get isConfigured => baseUrl.trim().isNotEmpty && model.trim().isNotEmpty;

  Map<String, dynamic> toJson() => {
        'baseUrl': baseUrl.trim(),
        'model': model.trim(),
        'apiKey': apiKey.trim(),
      };

  static AiConfig fromStorage(String? raw) {
    if (raw == null || raw.isEmpty) {
      return const AiConfig(baseUrl: '', model: '', apiKey: '');
    }
    try {
      final data = _map(jsonDecode(raw));
      return AiConfig(
        baseUrl: _text(data['baseUrl']),
        model: _text(data['model']),
        apiKey: _text(data['apiKey']),
      );
    } catch (_) {
      return const AiConfig(baseUrl: '', model: '', apiKey: '');
    }
  }
}

const aiDisclaimer =
    'AI guidance is advisory. CampusShield decides detections locally with signatures and heuristics; '
    'the assistant cannot change results, quarantine files, or edit settings.';
