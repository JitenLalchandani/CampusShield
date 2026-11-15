import 'package:material_ui/material_ui.dart';

import '../api.dart';
import '../app_state.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/common.dart';

class ProtectionScreen extends StatefulWidget {
  const ProtectionScreen({super.key, required this.state});

  final AppState state;

  @override
  State<ProtectionScreen> createState() => _ProtectionScreenState();
}

class _ProtectionScreenState extends State<ProtectionScreen> {
  bool _busy = false;
  bool _aiBusy = false;
  String? _aiSummary;
  String? _aiError;

  AppState get state => widget.state;

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

  Future<void> _run(String label, Future<void> Function() action) async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      await action();
      if (mounted) _say('$label finished.');
    } on ApiException catch (error) {
      _say(error.message, error: true);
    } catch (error) {
      _say('$error', error: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _scan(String scope) => _run(
        scope == 'full' ? 'Full scan' : 'Quick scan',
        () => state.runScan(scope),
      );

  Future<void> _customScan() async {
    final controller = TextEditingController();
    final path = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CsColors.card,
        title: const Text('Scan a folder or file'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Enter the full path on the computer running the CampusShield server.',
              style: TextStyle(color: CsColors.muted, fontSize: 13),
            ),
            const SizedBox(height: 14),
            TextField(
              controller: controller,
              autofocus: true,
              decoration: const InputDecoration(hintText: '/Users/you/Downloads'),
              onSubmitted: (value) => Navigator.pop(context, value),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text),
            child: const Text('Scan path'),
          ),
        ],
      ),
    );

    if (path == null || path.trim().isEmpty) return;
    await _run('Path scan', () => state.runScan('custom', path: path.trim()));
  }

  Future<void> _explain(Threat threat) async {
    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: CsColors.card,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (context) => _ExplainSheet(threat: threat, state: state),
    );
  }

  Future<void> _summarize() async {
    setState(() {
      _aiBusy = true;
      _aiError = null;
    });
    try {
      final text = await state.summarize();
      if (mounted) setState(() => _aiSummary = text);
    } on ApiException catch (error) {
      if (mounted) setState(() => _aiError = error.message);
    } finally {
      if (mounted) setState(() => _aiBusy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final protection = state.protection;
    final wide = MediaQuery.sizeOf(context).width >= 720;

    return ListView(
      padding: EdgeInsets.all(wide ? 26 : 16),
      children: [
        PageHeader(
          eyebrow: 'Protection',
          title: 'Device safety',
          subtitle: 'Local scans, real-time folder watch, and read-only posture checks in one score.',
          actions: [
            BusyButton(
              label: 'Check this computer',
              busy: _busy,
              icon: Icons.fact_check_outlined,
              filled: false,
              onPressed: () => _run('Device check', state.checkDevice),
            ),
          ],
        ),
        const SizedBox(height: 20),
        if (state.error != null) ...[
          ErrorBanner(message: state.error!, onRetry: () => state.refresh()),
          const SizedBox(height: 16),
        ],
        if (protection == null)
          const CsCard(child: LoadingBlock(label: 'Loading the cross-device score…'))
        else ...[
          _ScoreCard(state: state),
          const SizedBox(height: 16),
          _ScanCard(
            state: state,
            busy: _busy,
            onQuick: () => _scan('quick'),
            onFull: () => _scan('full'),
            onCustom: _customScan,
            onCancel: () {
              final active = state.activeScan;
              if (active != null) _run('Cancel', () => state.cancelScan(active.id));
            },
          ),
          const SizedBox(height: 16),
          _AiCard(
            busy: _aiBusy,
            summary: _aiSummary,
            error: _aiError,
            configured: state.ai.isConfigured,
            onRun: _summarize,
            onClear: () => setState(() {
              _aiSummary = null;
              _aiError = null;
            }),
          ),
          const SizedBox(height: 16),
          _FindingsCard(
            state: state,
            busy: _busy,
            onExplain: _explain,
            onQuarantine: (threat) => _run('Quarantine', () => state.quarantineThreat(threat)),
            onDelete: (threat) => _confirmDeleteThreat(threat),
          ),
          const SizedBox(height: 16),
          _DeviceCard(state: state, busy: _busy, run: _run),
          const SizedBox(height: 16),
          _QuarantineCard(state: state, busy: _busy, run: _run),
          const SizedBox(height: 16),
          const InfoNote(
            text: 'CampusShield is not a full antivirus. The signature set is small, heuristics catch specific '
                'patterns, and the folder watch cannot block execution from the user session. Scheduled scans '
                'start only while the server process is running.',
            icon: Icons.gpp_maybe_outlined,
            tone: CsColors.amber,
          ),
        ],
      ],
    );
  }

  Future<void> _confirmDeleteThreat(Threat threat) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CsColors.card,
        title: const Text('Delete this file?'),
        content: Text(
          '${threat.name} will be permanently removed from disk. This cannot be undone.',
          style: const TextStyle(color: CsColors.muted),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: CsColors.red, foregroundColor: Colors.white),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await _run('Delete', () => state.deleteThreat(threat));
    }
  }
}

class _ScoreCard extends StatelessWidget {
  const _ScoreCard({required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    final summary = state.score;
    final scanner = state.scanner;
    final schedule = scanner.preferences.schedule;
    final scheduleText = schedule.enabled
        ? 'Scheduled ${schedule.scope} scan ${schedule.frequency == 'weekly' ? 'every ${weekdayName(schedule.weekday)}' : 'daily'} '
            'at ${schedule.time}${scanner.scheduleNextRunAt != null ? ' · next ${formatDateTime(scanner.scheduleNextRunAt)}' : ''}.'
        : 'No scheduled scans. Turn one on in Settings.';

    return CsCard(
      child: LayoutBuilder(
        builder: (context, constraints) {
          final ring = ScoreRing(score: summary.average, grade: summary.grade);
          final details = Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  Pill(
                    label: scanner.available ? 'Scanner ready' : 'Scanner unavailable',
                    color: scanner.available ? CsColors.green : CsColors.amber,
                    icon: Icons.radar_rounded,
                  ),
                  Pill(
                    label: scanner.watch.enabled ? 'Real-time on' : 'Real-time off',
                    color: scanner.watch.enabled ? CsColors.green : CsColors.muted,
                    icon: Icons.visibility_outlined,
                  ),
                  Pill(
                    label: '${scanner.signatureCount} signatures',
                    color: CsColors.primary,
                    icon: Icons.fingerprint_rounded,
                  ),
                ],
              ),
              const SizedBox(height: 14),
              _StatRow(
                label: 'Devices checked',
                value: '${summary.checked} of ${summary.total}',
              ),
              _StatRow(
                label: 'Weakest device',
                value: summary.weakestName == null
                    ? 'None yet'
                    : '${summary.weakestName} (${summary.weakestScore?.round() ?? '—'})',
              ),
              _StatRow(label: 'Signature set', value: scanner.signatureVersion.isEmpty ? 'Unknown' : scanner.signatureVersion),
              _StatRow(label: 'Next scan', value: schedule.enabled ? formatDateTime(scanner.scheduleNextRunAt) : 'Not scheduled'),
              const SizedBox(height: 10),
              Text(scheduleText, style: const TextStyle(color: CsColors.faint, fontSize: 12, height: 1.4)),
            ],
          );

          if (constraints.maxWidth >= 620) {
            return Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                ring,
                const SizedBox(width: 28),
                Expanded(child: details),
              ],
            );
          }

          return Column(
            children: [
              ring,
              const SizedBox(height: 18),
              details,
            ],
          );
        },
      ),
    );
  }
}

class _StatRow extends StatelessWidget {
  const _StatRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          SizedBox(
            width: 118,
            child: Text(label, style: const TextStyle(color: CsColors.faint, fontSize: 12)),
          ),
          Expanded(
            child: Text(value, style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
          ),
        ],
      ),
    );
  }
}

class _ScanCard extends StatelessWidget {
  const _ScanCard({
    required this.state,
    required this.busy,
    required this.onQuick,
    required this.onFull,
    required this.onCustom,
    required this.onCancel,
  });

  final AppState state;
  final bool busy;
  final VoidCallback onQuick;
  final VoidCallback onFull;
  final VoidCallback onCustom;
  final VoidCallback onCancel;

  @override
  Widget build(BuildContext context) {
    final scanner = state.scanner;
    final active = state.activeScan;
    ScanRecord? last;
    for (final scan in state.scans) {
      if (scan.scope != 'realtime') {
        last = scan;
        break;
      }
    }
    final blocked = last?.errors ?? const <ScanError>[];

    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionTitle(
            title: 'Malware scan',
            caption: 'SHA-256 signatures, disguised file types, and script patterns. Files never leave this machine.',
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              BusyButton(
                label: 'Quick scan',
                busy: busy && active == null,
                icon: Icons.bolt_rounded,
                onPressed: active != null ? null : onQuick,
              ),
              BusyButton(
                label: 'Full scan',
                icon: Icons.manage_search_rounded,
                filled: false,
                onPressed: active != null ? null : onFull,
              ),
              BusyButton(
                label: 'Scan a path',
                icon: Icons.folder_open_rounded,
                filled: false,
                onPressed: active != null ? null : onCustom,
              ),
              if (active != null)
                BusyButton(
                  label: 'Cancel scan',
                  icon: Icons.stop_circle_outlined,
                  filled: false,
                  onPressed: onCancel,
                ),
            ],
          ),
          if (active != null) ...[
            const SizedBox(height: 18),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: CsColors.primary.withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: CsColors.primary.withValues(alpha: 0.25)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2, color: CsColors.primary),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          'Scanning ${active.scope == 'custom' ? 'the selected path' : '${active.scope} locations'} · '
                          '${formatCount(active.filesScanned)} files so far',
                          style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  const LinearProgressIndicator(
                    minHeight: 5,
                    backgroundColor: CsColors.border,
                    color: CsColors.primary,
                  ),
                ],
              ),
            ),
          ],
          if (last != null) ...[
            const SizedBox(height: 18),
            const Divider(),
            const SizedBox(height: 10),
            Wrap(
              spacing: 18,
              runSpacing: 8,
              children: [
                _MiniStat(label: 'Last scan', value: relativeTime(last.finishedAt ?? last.startedAt)),
                _MiniStat(label: 'Files', value: formatCount(last.filesScanned)),
                _MiniStat(label: 'Data', value: formatBytes(last.bytesScanned)),
                _MiniStat(
                  label: 'Findings',
                  value: '${last.openThreats.length}',
                  color: last.openThreats.isEmpty ? CsColors.green : CsColors.red,
                ),
              ],
            ),
            if (last.truncated) ...[
              const SizedBox(height: 10),
              const InfoNote(
                text: 'This scan hit its file or time budget and stopped early. Run a full scan or narrow the scope.',
                icon: Icons.timer_outlined,
                tone: CsColors.amber,
              ),
            ],
            if (blocked.isNotEmpty) ...[
              const SizedBox(height: 10),
              InfoNote(
                text: '${blocked.length} folder${blocked.length == 1 ? '' : 's'} could not be read '
                    '(${blocked.map((error) => error.path.split('/').last).take(3).join(', ')}). '
                    'The scan covered only the files it could open. Grant Full Disk Access, then scan again.',
                icon: Icons.folder_off_outlined,
                tone: CsColors.amber,
              ),
            ],
          ],
          const SizedBox(height: 14),
          Row(
            children: [
              const Expanded(
                child: Text(
                  'Signatures are bundled with the app. Add a trusted feed or refresh an existing one in Settings.',
                  style: TextStyle(color: CsColors.faint, fontSize: 11.5, height: 1.4),
                ),
              ),
              if (!scanner.available)
                const Pill(label: 'Scanner unavailable', color: CsColors.amber, icon: Icons.block_rounded),
            ],
          ),
        ],
      ),
    );
  }
}

class _MiniStat extends StatelessWidget {
  const _MiniStat({required this.label, required this.value, this.color});

  final String label;
  final String value;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label.toUpperCase(), style: const TextStyle(color: CsColors.faint, fontSize: 9.5, letterSpacing: 1)),
        const SizedBox(height: 3),
        Text(value, style: TextStyle(color: color ?? CsColors.text, fontSize: 13, fontWeight: FontWeight.w700)),
      ],
    );
  }
}

class _AiCard extends StatelessWidget {
  const _AiCard({
    required this.busy,
    required this.summary,
    required this.error,
    required this.configured,
    required this.onRun,
    required this.onClear,
  });

  final bool busy;
  final String? summary;
  final String? error;
  final bool configured;
  final VoidCallback onRun;
  final VoidCallback onClear;

  @override
  Widget build(BuildContext context) {
    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionTitle(
            title: 'AI assistant',
            caption: configured
                ? 'Ask your configured endpoint to explain the current protection state. Advisory only.'
                : 'Connect an OpenAI-compatible endpoint in Settings to explain findings. Off until you configure it.',
            trailing: BusyButton(
              label: summary == null ? 'Summarize findings' : 'Summarize again',
              busy: busy,
              icon: Icons.auto_awesome_rounded,
              filled: false,
              onPressed: configured ? onRun : null,
            ),
          ),
          if (error != null) ...[
            const SizedBox(height: 12),
            InfoNote(text: error!, icon: Icons.error_outline_rounded, tone: CsColors.red),
          ],
          if (summary != null) ...[
            const SizedBox(height: 14),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: CsColors.primary.withValues(alpha: 0.05),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: CsColors.primary.withValues(alpha: 0.25)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.auto_awesome_rounded, size: 16, color: CsColors.primary),
                      const SizedBox(width: 8),
                      const Expanded(
                        child: Text('AI summary', style: TextStyle(fontWeight: FontWeight.w700, fontSize: 13)),
                      ),
                      IconButton(
                        visualDensity: VisualDensity.compact,
                        tooltip: 'Clear',
                        onPressed: onClear,
                        icon: const Icon(Icons.close_rounded, size: 18, color: CsColors.muted),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  SelectableText(summary!, style: const TextStyle(fontSize: 13, height: 1.55)),
                  const SizedBox(height: 10),
                  const Text(aiDisclaimer, style: TextStyle(color: CsColors.faint, fontSize: 10.5, height: 1.4)),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _FindingsCard extends StatelessWidget {
  const _FindingsCard({
    required this.state,
    required this.busy,
    required this.onExplain,
    required this.onQuarantine,
    required this.onDelete,
  });

  final AppState state;
  final bool busy;
  final ValueChanged<Threat> onExplain;
  final ValueChanged<Threat> onQuarantine;
  final ValueChanged<Threat> onDelete;

  @override
  Widget build(BuildContext context) {
    final findings = state.openThreats;
    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionTitle(
            title: 'Open findings',
            caption: findings.isEmpty
                ? 'No unresolved findings from recent scans.'
                : '${findings.length} file${findings.length == 1 ? '' : 's'} need a decision.',
            trailing: Pill(
              label: findings.isEmpty ? 'Clear' : '${findings.length} open',
              color: findings.isEmpty ? CsColors.green : CsColors.red,
            ),
          ),
          if (findings.isEmpty)
            const EmptyState(
              icon: Icons.verified_outlined,
              title: 'Nothing to review',
              body: 'A clean result means these rules matched nothing — it is not a guarantee that a file is safe.',
            )
          else
            ...findings.map(
              (threat) => _FindingTile(
                threat: threat,
                busy: busy,
                onExplain: () => onExplain(threat),
                onQuarantine: () => onQuarantine(threat),
                onDelete: () => onDelete(threat),
              ),
            ),
        ],
      ),
    );
  }
}

class _FindingTile extends StatelessWidget {
  const _FindingTile({
    required this.threat,
    required this.busy,
    required this.onExplain,
    required this.onQuarantine,
    required this.onDelete,
  });

  final Threat threat;
  final bool busy;
  final VoidCallback onExplain;
  final VoidCallback onQuarantine;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    final color = severityColor(threat.severity);
    return Container(
      margin: const EdgeInsets.only(top: 12),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: CsColors.cardAlt,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: CsColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.description_outlined, size: 20, color: color),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(threat.name, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14)),
                    const SizedBox(height: 3),
                    Text(
                      threat.filePath,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(color: CsColors.faint, fontSize: 11.5, height: 1.35),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Pill(label: threat.severity.toUpperCase(), color: color),
            ],
          ),
          if (threat.reasons.isNotEmpty) ...[
            const SizedBox(height: 10),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: threat.reasons
                  .map((reason) => Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: CsColors.surface,
                          borderRadius: BorderRadius.circular(999),
                          border: Border.all(color: CsColors.border),
                        ),
                        child: Text(reason.label, style: const TextStyle(color: CsColors.muted, fontSize: 10.5)),
                      ))
                  .toList(),
            ),
          ],
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              OutlinedButton.icon(
                onPressed: busy ? null : onExplain,
                icon: const Icon(Icons.auto_awesome_rounded, size: 16),
                label: const Text('Explain'),
              ),
              OutlinedButton.icon(
                onPressed: busy ? null : onQuarantine,
                icon: const Icon(Icons.lock_outline_rounded, size: 16),
                label: const Text('Quarantine'),
              ),
              OutlinedButton.icon(
                onPressed: busy ? null : onDelete,
                icon: const Icon(Icons.delete_outline_rounded, size: 16, color: CsColors.red),
                label: const Text('Delete', style: TextStyle(color: CsColors.red)),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _DeviceCard extends StatelessWidget {
  const _DeviceCard({required this.state, required this.busy, required this.run});

  final AppState state;
  final bool busy;
  final Future<void> Function(String, Future<void> Function()) run;

  @override
  Widget build(BuildContext context) {
    final devices = state.devices;
    final host = state.protection?.host;
    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionTitle(
            title: 'Devices',
            caption: 'Checked devices feed the shared score. Linked devices stay "Not checked" until their own check runs.',
            trailing: TextButton.icon(
              onPressed: busy ? null : () => _addDeviceDialog(context),
              icon: const Icon(Icons.add_rounded, size: 17),
              label: const Text('Link device'),
            ),
          ),
          if (devices.isEmpty)
            const EmptyState(
              icon: Icons.devices_other_outlined,
              title: 'No devices linked',
              body: 'Run the device check or link a phone to start the shared score.',
            )
          else
            ...devices.map(
              (device) => _DeviceTile(
                device: device,
                isHost: host?.id == device.id,
                busy: busy,
                onRemove: () => run('Device removal', () => state.removeDevice(device.id)),
              ),
            ),
        ],
      ),
    );
  }

  Future<void> _addDeviceDialog(BuildContext context) async {
    final name = TextEditingController();
    var kind = 'phone';
    var platform = 'ios';
    final added = await showDialog<bool>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          backgroundColor: CsColors.card,
          title: const Text('Link a device'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: name,
                decoration: const InputDecoration(labelText: 'Device name', hintText: 'My phone'),
              ),
              const SizedBox(height: 14),
              DropdownButtonFormField<String>(
                isExpanded: true,
                initialValue: kind,
                decoration: const InputDecoration(labelText: 'Kind'),
                dropdownColor: CsColors.card,
                items: const [
                  DropdownMenuItem(value: 'phone', child: Text('Phone')),
                  DropdownMenuItem(value: 'tablet', child: Text('Tablet')),
                  DropdownMenuItem(value: 'computer', child: Text('Computer')),
                  DropdownMenuItem(value: 'browser', child: Text('Browser')),
                ],
                onChanged: (value) => setDialogState(() => kind = value ?? kind),
              ),
              const SizedBox(height: 14),
              DropdownButtonFormField<String>(
                isExpanded: true,
                initialValue: platform,
                decoration: const InputDecoration(labelText: 'Platform'),
                dropdownColor: CsColors.card,
                items: const [
                  DropdownMenuItem(value: 'ios', child: Text('iOS / iPadOS')),
                  DropdownMenuItem(value: 'android', child: Text('Android')),
                  DropdownMenuItem(value: 'darwin', child: Text('macOS')),
                  DropdownMenuItem(value: 'win32', child: Text('Windows')),
                  DropdownMenuItem(value: 'linux', child: Text('Linux')),
                  DropdownMenuItem(value: 'web', child: Text('Web')),
                ],
                onChanged: (value) => setDialogState(() => platform = value ?? platform),
              ),
            ],
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Link'),
            ),
          ],
        ),
      ),
    );

    if (added == true && name.text.trim().isNotEmpty) {
      await run(
        'Link device',
        () => state.addDevice(name: name.text.trim(), kind: kind, platform: platform),
      );
    }
  }
}

class _DeviceTile extends StatelessWidget {
  const _DeviceTile({
    required this.device,
    required this.isHost,
    required this.busy,
    required this.onRemove,
  });

  final Device device;
  final bool isHost;
  final bool busy;
  final VoidCallback onRemove;

  @override
  Widget build(BuildContext context) {
    final checks = device.checks;
    return Container(
      margin: const EdgeInsets.only(top: 12),
      decoration: BoxDecoration(
        color: CsColors.cardAlt,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: CsColors.border),
      ),
      child: ExpansionTile(
        shape: const Border(),
        collapsedShape: const Border(),
        tilePadding: const EdgeInsets.symmetric(horizontal: 14),
        childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
        leading: Icon(
          device.kind == 'phone'
              ? Icons.smartphone_rounded
              : device.kind == 'tablet'
                  ? Icons.tablet_mac_rounded
                  : device.kind == 'browser'
                      ? Icons.language_rounded
                      : Icons.laptop_mac_rounded,
          color: isHost ? CsColors.primary : CsColors.muted,
        ),
        title: Row(
          children: [
            Flexible(
              child: Text(
                device.name,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
              ),
            ),
            if (isHost) ...[
              const SizedBox(width: 8),
              const Pill(label: 'This host', color: CsColors.primary),
            ],
          ],
        ),
        subtitle: Text(
          '${device.platformLabel.isEmpty ? device.platform : device.platformLabel}'
          '${device.model.isNotEmpty ? ' · ${device.model}' : ''}',
          style: const TextStyle(color: CsColors.faint, fontSize: 11.5),
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              device.isChecked ? '${device.score!.round()}' : '—',
              style: TextStyle(
                color: gradeColor(device.score),
                fontSize: 18,
                fontWeight: FontWeight.w800,
              ),
            ),
            IconButton(
              tooltip: 'Remove device',
              onPressed: busy ? null : onRemove,
              icon: const Icon(Icons.close_rounded, size: 17, color: CsColors.faint),
            ),
          ],
        ),
        children: [
          if (checks.isEmpty)
            const Align(
              alignment: Alignment.centerLeft,
              child: Text('No posture checks recorded for this device.', style: TextStyle(color: CsColors.muted, fontSize: 12.5)),
            )
          else
            ...checks.map(
              (check) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 7),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      check.status == 'pass'
                          ? Icons.check_circle_outline_rounded
                          : check.status == 'unknown'
                              ? Icons.help_outline_rounded
                              : Icons.error_outline_rounded,
                      size: 17,
                      color: statusColor(check.status),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(check.title, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 12.5)),
                          const SizedBox(height: 2),
                          Text(check.detail, style: const TextStyle(color: CsColors.muted, fontSize: 11.5, height: 1.35)),
                          if (check.status == 'warn' || check.status == 'fail')
                            Padding(
                              padding: const EdgeInsets.only(top: 3),
                              child: Text(
                                check.recommendation,
                                style: const TextStyle(color: CsColors.amber, fontSize: 11.5, height: 1.35),
                              ),
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _QuarantineCard extends StatelessWidget {
  const _QuarantineCard({required this.state, required this.busy, required this.run});

  final AppState state;
  final bool busy;
  final Future<void> Function(String, Future<void> Function()) run;

  @override
  Widget build(BuildContext context) {
    final entries = state.quarantine;
    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionTitle(
            title: 'Quarantine',
            caption: 'Files moved into the app vault. Restoring puts the file back where it came from.',
            trailing: Pill(label: '${entries.length} held', color: entries.isEmpty ? CsColors.muted : CsColors.primary),
          ),
          if (entries.isEmpty)
            const EmptyState(
              icon: Icons.inventory_2_outlined,
              title: 'The vault is empty',
              body: 'Quarantined files stop counting against the score until you restore them.',
            )
          else
            ...entries.map(
              (entry) => Container(
                margin: const EdgeInsets.only(top: 12),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: CsColors.cardAlt,
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: CsColors.border),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.lock_outline_rounded, size: 18, color: severityColor(entry.severity)),
                        const SizedBox(width: 9),
                        Expanded(
                          child: Text(entry.name, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13.5)),
                        ),
                        Pill(label: entry.severity.toUpperCase(), color: severityColor(entry.severity)),
                      ],
                    ),
                    const SizedBox(height: 6),
                    Text(
                      entry.originalPath,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(color: CsColors.faint, fontSize: 11.5),
                    ),
                    const SizedBox(height: 10),
                    Wrap(
                      spacing: 8,
                      children: [
                        OutlinedButton(
                          onPressed: busy ? null : () => run('Restore', () => state.restoreQuarantine(entry)),
                          child: const Text('Restore'),
                        ),
                        OutlinedButton(
                          onPressed: busy ? null : () => run('Delete', () => state.deleteQuarantine(entry)),
                          child: const Text('Delete forever', style: TextStyle(color: CsColors.red)),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _ExplainSheet extends StatelessWidget {
  const _ExplainSheet({required this.threat, required this.state});

  final Threat threat;
  final AppState state;

  @override
  Widget build(BuildContext context) {
    final future = state.explain(threat);
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(22, 0, 22, 24),
        child: FutureBuilder<String>(
          future: future,
          builder: (context, snapshot) {
            return Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Icon(Icons.auto_awesome_rounded, color: CsColors.primary, size: 20),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'AI explanation · ${threat.name}',
                        style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
                      ),
                    ),
                    Pill(label: threat.severity.toUpperCase(), color: severityColor(threat.severity)),
                  ],
                ),
                const SizedBox(height: 16),
                if (snapshot.connectionState != ConnectionState.done)
                  const Padding(
                    padding: EdgeInsets.symmetric(vertical: 26),
                    child: Row(
                      children: [
                        SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2, color: CsColors.primary),
                        ),
                        SizedBox(width: 12),
                        Text('Asking your configured endpoint…', style: TextStyle(color: CsColors.muted, fontSize: 13)),
                      ],
                    ),
                  )
                else if (snapshot.hasError)
                  InfoNote(
                    text: '${snapshot.error}',
                    icon: Icons.error_outline_rounded,
                    tone: CsColors.red,
                  )
                else
                  ConstrainedBox(
                    constraints: BoxConstraints(maxHeight: MediaQuery.sizeOf(context).height * 0.55),
                    child: SingleChildScrollView(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          SelectableText(
                            snapshot.data ?? '',
                            style: const TextStyle(fontSize: 13.5, height: 1.6),
                          ),
                          const SizedBox(height: 16),
                          const Text(aiDisclaimer, style: TextStyle(color: CsColors.faint, fontSize: 11, height: 1.45)),
                        ],
                      ),
                    ),
                  ),
              ],
            );
          },
        ),
      ),
    );
  }
}
