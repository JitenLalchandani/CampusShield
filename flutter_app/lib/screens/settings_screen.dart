import 'package:material_ui/material_ui.dart';

import '../api.dart';
import '../app_state.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/common.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.state});

  final AppState state;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final TextEditingController _base;
  late final TextEditingController _token;
  late final TextEditingController _aiBase;
  late final TextEditingController _aiModel;
  late final TextEditingController _aiKey;

  late bool _realtime;
  late bool _notify;
  late bool _scheduleEnabled;
  late String _scope;
  late String _frequency;
  late int _weekday;
  late String _time;
  late List<String> _exclusions;

  bool _savingPrefs = false;
  bool _savingConnection = false;
  bool _savingAi = false;
  bool _testingAi = false;
  String? _connectionNote;
  String? _aiNote;
  bool _aiNoteError = false;

  AppState get state => widget.state;

  @override
  void initState() {
    super.initState();
    _base = TextEditingController(text: state.apiBase);
    _token = TextEditingController(text: state.apiToken);
    _aiBase = TextEditingController(text: state.ai.baseUrl);
    _aiModel = TextEditingController(text: state.ai.model);
    _aiKey = TextEditingController(text: state.ai.apiKey);

    final prefs = state.scanner.preferences;
    _realtime = prefs.realtime;
    _notify = prefs.notify;
    _scheduleEnabled = prefs.schedule.enabled;
    _scope = prefs.schedule.scope;
    _frequency = prefs.schedule.frequency;
    _weekday = prefs.schedule.weekday;
    _time = prefs.schedule.time;
    _exclusions = [...prefs.exclusions];
  }

  @override
  void dispose() {
    _base.dispose();
    _token.dispose();
    _aiBase.dispose();
    _aiModel.dispose();
    _aiKey.dispose();
    super.dispose();
  }

  void _say(String message, {bool error = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: error ? const Color(0xFF3A1220) : null,
        duration: Duration(seconds: error ? 6 : 4),
      ),
    );
  }

  Future<void> _saveConnection() async {
    setState(() {
      _savingConnection = true;
      _connectionNote = null;
    });

    try {
      await state.saveConnection(baseUrl: _base.text, token: _token.text);
      final health = await state.api.health();
      if (!mounted) return;
      setState(() {
        _connectionNote = 'Connected to ${health['app']} ${health['version']} · '
            '${health['platformLabel']} · ${health['storage']}';
      });
      _say('Connection saved.');
    } on ApiException catch (error) {
      if (mounted) setState(() => _connectionNote = error.message);
      _say(error.message, error: true);
    } finally {
      if (mounted) setState(() => _savingConnection = false);
    }
  }

  Future<void> _savePreferences() async {
    setState(() => _savingPrefs = true);
    try {
      final saved = await state.savePreferences(
        Preferences(
          realtime: _realtime,
          notify: _notify,
          exclusions: _exclusions,
          schedule: Schedule(
            enabled: _scheduleEnabled,
            scope: _scope,
            frequency: _frequency,
            weekday: _weekday,
            time: _time,
          ),
        ),
      );

      if (!mounted) return;
      setState(() {
        _realtime = saved.realtime;
        _notify = saved.notify;
        _exclusions = [...saved.exclusions];
        _scheduleEnabled = saved.schedule.enabled;
        _scope = saved.schedule.scope;
        _frequency = saved.schedule.frequency;
        _weekday = saved.schedule.weekday;
        _time = saved.schedule.time;
      });
      _say('Protection settings saved.');
    } on ApiException catch (error) {
      _say(error.message, error: true);
    } finally {
      if (mounted) setState(() => _savingPrefs = false);
    }
  }

  Future<void> _pickTime() async {
    final parts = _time.split(':');
    final initial = TimeOfDay(
      hour: int.tryParse(parts.isNotEmpty ? parts[0] : '9') ?? 9,
      minute: int.tryParse(parts.length > 1 ? parts[1] : '0') ?? 0,
    );
    final picked = await showTimePicker(context: context, initialTime: initial);
    if (picked == null) return;
    setState(() {
      _time = '${picked.hour.toString().padLeft(2, '0')}:${picked.minute.toString().padLeft(2, '0')}';
    });
  }

  Future<void> _addExclusion() async {
    final controller = TextEditingController();
    final path = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CsColors.card,
        title: const Text('Exclude a folder'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Automatic and scheduled scans skip this folder. A custom scan of it still runs.',
              style: TextStyle(color: CsColors.muted, fontSize: 12.5),
            ),
            const SizedBox(height: 14),
            TextField(
              controller: controller,
              autofocus: true,
              decoration: const InputDecoration(hintText: '/Users/you/Projects/vendor'),
              onSubmitted: (value) => Navigator.pop(context, value),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, controller.text), child: const Text('Add')),
        ],
      ),
    );

    if (path == null || path.trim().isEmpty) return;
    setState(() => _exclusions = {..._exclusions, path.trim()}.toList());
  }

  Future<void> _updateSignatures() async {
    try {
      final message = await state.updateSignatures();
      _say(message);
    } on ApiException catch (error) {
      _say(error.message, error: true);
    }
  }

  Future<void> _saveAi({bool test = false}) async {
    final base = _aiBase.text.trim();
    final model = _aiModel.text.trim();
    if (base.isEmpty && model.isEmpty) {
      await state.saveAi(const AiConfig(baseUrl: '', model: '', apiKey: ''));
      setState(() {
        _aiNote = 'The AI assistant is disconnected.';
        _aiNoteError = false;
      });
      return;
    }

    if (base.isEmpty || model.isEmpty) {
      setState(() {
        _aiNote = 'Enter both a base URL and a model name.';
        _aiNoteError = true;
      });
      return;
    }

    setState(() {
      _savingAi = true;
      _testingAi = test;
      _aiNote = null;
      _aiNoteError = false;
    });

    try {
      final config = AiConfig(baseUrl: base, model: model, apiKey: _aiKey.text.trim());
      await state.saveAi(config);
      if (test) {
        final reply = await state.testAi();
        if (mounted) {
          setState(() {
            _aiNote = 'Provider answered: ${reply.length > 180 ? '${reply.substring(0, 180)}…' : reply}';
            _aiNoteError = false;
          });
        }
      } else if (mounted) {
        setState(() {
          _aiNote = 'AI settings saved in this app’s local storage.';
          _aiNoteError = false;
        });
      }
    } on ApiException catch (error) {
      if (mounted) {
        setState(() {
          _aiNote = error.message;
          _aiNoteError = true;
        });
      }
    } finally {
      if (mounted) {
        setState(() {
          _savingAi = false;
          _testingAi = false;
        });
      }
    }
  }

  Future<void> _removeAi() async {
    _aiBase.clear();
    _aiModel.clear();
    _aiKey.clear();
    await state.saveAi(const AiConfig(baseUrl: '', model: '', apiKey: ''));
    if (!mounted) return;
    setState(() {
      _aiNote = 'The AI assistant is disconnected.';
      _aiNoteError = false;
    });
    _say('AI settings removed.');
  }

  Future<void> _clearData() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CsColors.card,
        title: const Text('Clear all data?'),
        content: const Text(
          'This removes events, decisions, devices, scans, quarantine records, and saved protection settings from the server. Files already quarantined on disk are deleted too.',
          style: TextStyle(color: CsColors.muted, fontSize: 13, height: 1.45),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: CsColors.red, foregroundColor: Colors.white),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Clear everything'),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    try {
      await state.clearAllData();
      _say('All server data was cleared.');
    } on ApiException catch (error) {
      _say(error.message, error: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= 720;
    final scanner = state.scanner;
    final protection = state.protection;

    return ListView(
      padding: EdgeInsets.all(wide ? 26 : 16),
      children: [
        const PageHeader(
          eyebrow: 'Settings',
          title: 'Server, protection, and AI',
          subtitle: 'These settings are stored by the server or in this app’s local storage. Nothing is sent to the developer.',
        ),
        const SizedBox(height: 20),
        _card(
          title: 'Server connection',
          caption: 'The Flutter app talks to the same API as the website. Use HTTPS for anything beyond localhost.',
          children: [
            TextField(
              controller: _base,
              decoration: const InputDecoration(
                labelText: 'API base URL',
                hintText: 'Same origin — http://127.0.0.1:3999',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _token,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'API access token',
                hintText: 'Not required unless the server sets one',
              ),
            ),
            const SizedBox(height: 14),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                BusyButton(
                  label: 'Save & test',
                  busy: _savingConnection,
                  icon: Icons.link_rounded,
                  onPressed: _saveConnection,
                ),
                BusyButton(
                  label: 'Use same origin',
                  filled: false,
                  icon: Icons.language_rounded,
                  onPressed: () {
                    _base.clear();
                    _saveConnection();
                  },
                ),
              ],
            ),
            if (_connectionNote != null) ...[
              const SizedBox(height: 12),
              InfoNote(
                text: _connectionNote!,
                icon: _connectionNote!.startsWith('Connected') ? Icons.check_circle_outline_rounded : Icons.error_outline_rounded,
                tone: _connectionNote!.startsWith('Connected') ? CsColors.green : CsColors.red,
              ),
            ],
          ],
        ),
        const SizedBox(height: 16),
        _card(
          title: 'Protection',
          caption: 'Real-time, notifications, exclusions, and the scan schedule are saved by the server.',
          children: [
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Real-time folder watch', style: TextStyle(fontSize: 13.5)),
              subtitle: const Text(
                'Scans new files in quick-scan folders. User space only — it cannot block execution.',
                style: TextStyle(color: CsColors.faint, fontSize: 11.5),
              ),
              value: _realtime,
              onChanged: scanner.watchSupported ? (value) => setState(() => _realtime = value) : null,
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Notify about new findings', style: TextStyle(fontSize: 13.5)),
              subtitle: const Text(
                'The Flutter app shows an in-app alert. The Electron build also shows an OS notification.',
                style: TextStyle(color: CsColors.faint, fontSize: 11.5),
              ),
              value: _notify,
              onChanged: (value) => setState(() => _notify = value),
            ),
            const Divider(height: 24),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Scheduled scans', style: TextStyle(fontSize: 13.5)),
              subtitle: Text(
                scanner.scheduleNextRunAt != null
                    ? 'Next run ${formatDateTime(scanner.scheduleNextRunAt)}'
                    : 'Runs only while the server process is open.',
                style: const TextStyle(color: CsColors.faint, fontSize: 11.5),
              ),
              value: _scheduleEnabled,
              onChanged: (value) => setState(() => _scheduleEnabled = value),
            ),
            if (_scheduleEnabled) ...[
              const SizedBox(height: 4),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  SizedBox(
                    width: 150,
                    child: DropdownButtonFormField<String>(
                      isExpanded: true,
                      initialValue: _scope,
                      decoration: const InputDecoration(labelText: 'Scope'),
                      dropdownColor: CsColors.card,
                      items: const [
                        DropdownMenuItem(value: 'quick', child: Text('Quick scan')),
                        DropdownMenuItem(value: 'full', child: Text('Full scan')),
                      ],
                      onChanged: (value) => setState(() => _scope = value ?? 'quick'),
                    ),
                  ),
                  SizedBox(
                    width: 150,
                    child: DropdownButtonFormField<String>(
                      isExpanded: true,
                      initialValue: _frequency,
                      decoration: const InputDecoration(labelText: 'Frequency'),
                      dropdownColor: CsColors.card,
                      items: const [
                        DropdownMenuItem(value: 'daily', child: Text('Daily')),
                        DropdownMenuItem(value: 'weekly', child: Text('Weekly')),
                      ],
                      onChanged: (value) => setState(() => _frequency = value ?? 'daily'),
                    ),
                  ),
                  if (_frequency == 'weekly')
                    SizedBox(
                      width: 160,
                      child: DropdownButtonFormField<int>(
                        isExpanded: true,
                        initialValue: _weekday,
                        decoration: const InputDecoration(labelText: 'Weekday'),
                        dropdownColor: CsColors.card,
                        items: List.generate(
                          7,
                          (index) => DropdownMenuItem(value: index, child: Text(weekdayName(index))),
                        ),
                        onChanged: (value) => setState(() => _weekday = value ?? 1),
                      ),
                    ),
                  SizedBox(
                    width: 140,
                    child: OutlinedButton.icon(
                      onPressed: _pickTime,
                      icon: const Icon(Icons.schedule_rounded, size: 17),
                      label: Text(_time),
                    ),
                  ),
                ],
              ),
            ],
            const Divider(height: 24),
            const Text('Excluded folders', style: TextStyle(fontSize: 13.5, fontWeight: FontWeight.w600)),
            const SizedBox(height: 4),
            const Text(
              'Automatic and scheduled scans skip these paths. A custom scan always runs.',
              style: TextStyle(color: CsColors.faint, fontSize: 11.5),
            ),
            const SizedBox(height: 10),
            if (_exclusions.isEmpty)
              const Text('No exclusions.', style: TextStyle(color: CsColors.faint, fontSize: 12))
            else
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: _exclusions
                    .map((path) => Chip(
                          label: Text(path, overflow: TextOverflow.ellipsis),
                          deleteIcon: const Icon(Icons.close_rounded, size: 14),
                          onDeleted: () => setState(() => _exclusions = _exclusions.where((item) => item != path).toList()),
                        ))
                    .toList(),
              ),
            const SizedBox(height: 8),
            TextButton.icon(
              onPressed: _addExclusion,
              icon: const Icon(Icons.add_rounded, size: 17),
              label: const Text('Add folder'),
            ),
            const SizedBox(height: 10),
            BusyButton(
              label: 'Save protection settings',
              busy: _savingPrefs,
              icon: Icons.save_outlined,
              onPressed: _savePreferences,
            ),
          ],
        ),
        const SizedBox(height: 16),
        _card(
          title: 'Signatures',
          caption: 'The built-in set plus an optional HTTPS feed configured on the server.',
          children: [
            KeyValueRow(label: 'Version', value: scanner.signatureVersion.isEmpty ? 'Unknown' : scanner.signatureVersion),
            KeyValueRow(label: 'Hashes', value: '${scanner.signatureCount}'),
            KeyValueRow(label: 'Feed', value: scanner.remoteFeedState),
            if (scanner.signatureNote.isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(scanner.signatureNote, style: const TextStyle(color: CsColors.faint, fontSize: 11.5, height: 1.4)),
            ],
            if (scanner.remoteFeedMessage != null) ...[
              const SizedBox(height: 8),
              InfoNote(text: scanner.remoteFeedMessage!, icon: Icons.cloud_sync_outlined),
            ],
            const SizedBox(height: 12),
            BusyButton(
              label: 'Check for signature updates',
              icon: Icons.sync_rounded,
              filled: false,
              onPressed: _updateSignatures,
            ),
          ],
        ),
        const SizedBox(height: 16),
        _card(
          title: 'AI assistant',
          caption: 'Optional. The key stays in this app’s local storage and is sent to the server with each request; the server does not save it.',
          children: [
            TextField(
              controller: _aiBase,
              decoration: const InputDecoration(
                labelText: 'Base URL',
                hintText: 'https://api.openai.com/v1  ·  http://localhost:11434/v1',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _aiModel,
              decoration: const InputDecoration(labelText: 'Model', hintText: 'gpt-4o-mini'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _aiKey,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'API key',
                hintText: 'Leave empty for a local model',
              ),
            ),
            const SizedBox(height: 14),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                BusyButton(
                  label: 'Save',
                  busy: _savingAi && !_testingAi,
                  icon: Icons.save_outlined,
                  onPressed: () => _saveAi(),
                ),
                BusyButton(
                  label: 'Save & test',
                  busy: _testingAi,
                  icon: Icons.network_check_rounded,
                  filled: false,
                  onPressed: () => _saveAi(test: true),
                ),
                TextButton(
                  onPressed: _savingAi ? null : _removeAi,
                  child: const Text('Remove', style: TextStyle(color: CsColors.red)),
                ),
              ],
            ),
            if (_aiNote != null) ...[
              const SizedBox(height: 12),
              InfoNote(
                text: _aiNote!,
                icon: _aiNoteError ? Icons.error_outline_rounded : Icons.check_circle_outline_rounded,
                tone: _aiNoteError ? CsColors.red : CsColors.green,
              ),
            ],
            const SizedBox(height: 10),
            const Text(
              'Remote endpoints must use HTTPS. Plain HTTP is allowed only for localhost. The assistant is advisory: it '
              'explains findings and never decides whether a file is malicious.',
              style: TextStyle(color: CsColors.faint, fontSize: 11, height: 1.45),
            ),
          ],
        ),
        const SizedBox(height: 16),
        _card(
          title: 'Data controls',
          caption: 'Clear everything the server stores for this workspace.',
          children: [
            OutlinedButton.icon(
              onPressed: _clearData,
              icon: const Icon(Icons.delete_forever_outlined, size: 18, color: CsColors.red),
              label: const Text('Clear all data', style: TextStyle(color: CsColors.red)),
            ),
          ],
        ),
        const SizedBox(height: 16),
        _card(
          title: 'About this build',
          caption: 'CampusShield Flutter client 1.0.0',
          children: [
            KeyValueRow(label: 'API', value: state.api.baseUrl),
            KeyValueRow(label: 'Platform', value: protection?.platformLabel ?? 'Not connected'),
            KeyValueRow(label: 'Storage', value: protection?.storage ?? 'Unknown'),
            KeyValueRow(label: 'Rules', value: state.overview.dataSource),
            const SizedBox(height: 10),
            const Text(
              'The Flutter client is a real interface to the same local API as the website. On iOS and the Mac App Store '
              'the sandbox still prevents scanning other apps’ files, and a user-space watch cannot block execution. '
              'A clean scan is not a guarantee that a file is safe.',
              style: TextStyle(color: CsColors.faint, fontSize: 11, height: 1.5),
            ),
          ],
        ),
      ],
    );
  }

  Widget _card({
    required String title,
    required String caption,
    required List<Widget> children,
  }) {
    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionTitle(title: title, caption: caption),
          const SizedBox(height: 16),
          ...children,
        ],
      ),
    );
  }
}
