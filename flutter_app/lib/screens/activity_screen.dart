import 'package:material_ui/material_ui.dart';

import '../app_state.dart';
import '../theme.dart';
import '../widgets/common.dart';

class ActivityScreen extends StatefulWidget {
  const ActivityScreen({super.key, required this.state});

  final AppState state;

  @override
  State<ActivityScreen> createState() => _ActivityScreenState();
}

class _ActivityScreenState extends State<ActivityScreen> {
  String _kind = 'all';

  static const _kinds = ['all', 'device', 'scan', 'admin', 'ai', 'action'];

  IconData _icon(String kind) {
    switch (kind) {
      case 'device':
        return Icons.fact_check_outlined;
      case 'scan':
        return Icons.radar_rounded;
      case 'admin':
        return Icons.settings_outlined;
      case 'ai':
        return Icons.auto_awesome_rounded;
      case 'action':
        return Icons.rule_rounded;
      default:
        return Icons.history_rounded;
    }
  }

  Color _tone(String kind) {
    switch (kind) {
      case 'scan':
        return CsColors.primary;
      case 'ai':
        return CsColors.green;
      case 'admin':
        return CsColors.amber;
      default:
        return CsColors.muted;
    }
  }

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= 720;
    final entries = _kind == 'all'
        ? widget.state.activity
        : widget.state.activity.where((entry) => entry.kind == _kind).toList();

    return ListView(
      padding: EdgeInsets.all(wide ? 26 : 16),
      children: [
        PageHeader(
          eyebrow: 'Audit',
          title: 'Activity',
          subtitle: 'Device checks, scans, AI requests, and operator decisions in one timeline.',
          actions: [
            BusyButton(
              label: 'Refresh',
              busy: widget.state.refreshing,
              icon: Icons.refresh_rounded,
              filled: false,
              onPressed: () => widget.state.refresh(),
            ),
          ],
        ),
        const SizedBox(height: 20),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: _kinds
              .map((kind) => FilterChip(
                    label: Text(kind == 'all' ? 'All' : kind[0].toUpperCase() + kind.substring(1)),
                    selected: _kind == kind,
                    onSelected: (_) => setState(() => _kind = kind),
                    selectedColor: CsColors.primary.withValues(alpha: 0.18),
                    checkmarkColor: CsColors.primary,
                  ))
              .toList(),
        ),
        const SizedBox(height: 16),
        CsCard(
          child: entries.isEmpty
              ? const EmptyState(
                  icon: Icons.history_rounded,
                  title: 'No activity yet',
                  body: 'Run a device check or a scan and it will appear here with the exact message the server recorded.',
                )
              : Column(
                  children: entries.map((entry) {
                    final tone = _tone(entry.kind);
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 14),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Container(
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: tone.withValues(alpha: 0.1),
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(color: tone.withValues(alpha: 0.3)),
                            ),
                            child: Icon(_icon(entry.kind), size: 16, color: tone),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(entry.message, style: const TextStyle(fontSize: 13, height: 1.4)),
                                const SizedBox(height: 4),
                                Text(
                                  '${entry.kind} · ${formatDateTime(entry.time)} · ${relativeTime(entry.time)}',
                                  style: const TextStyle(color: CsColors.faint, fontSize: 11),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    );
                  }).toList(),
                ),
        ),
        const SizedBox(height: 16),
        InfoNote(
          text: widget.state.protection == null
              ? 'The audit trail is stored by the server you connect to.'
              : '${widget.state.overview.auditTotal} audit entries are stored in ${widget.state.protection!.storage}.',
          icon: Icons.storage_outlined,
        ),
      ],
    );
  }
}
