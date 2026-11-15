import 'package:material_ui/material_ui.dart';

import '../api.dart';
import '../app_state.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/common.dart';

class ThreatsScreen extends StatefulWidget {
  const ThreatsScreen({super.key, required this.state});

  final AppState state;

  @override
  State<ThreatsScreen> createState() => _ThreatsScreenState();
}

class _ThreatsScreenState extends State<ThreatsScreen> {
  List<EventItem> _events = [];
  int _total = 0;
  int _allTotal = 0;
  bool _loading = true;
  String? _error;
  String _severity = 'all';
  String _status = 'all';
  bool _started = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (!_started) {
      _started = true;
      _load();
    }
  }

  Future<void> _load() async {
    if (mounted) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }

    try {
      final page = await widget.state.api.events(severity: _severity, status: _status);
      if (!mounted) return;
      setState(() {
        _events = page.events;
        _total = page.total;
        _allTotal = page.allTotal;
      });
    } on ApiException catch (error) {
      if (!mounted) return;
      setState(() => _error = error.message);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _act(EventItem event, String action) async {
    try {
      await widget.state.api.actOnEvent(event.id, action);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            action == 'Contain'
                ? '${event.type} marked contained. This records a decision only.'
                : '${event.type} marked $action.',
          ),
        ),
      );
      await _load();
      await widget.state.refresh(silent: true);
    } on ApiException catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(error.message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= 720;
    final filtered = _severity != 'all' || _status != 'all';

    return ListView(
      padding: EdgeInsets.all(wide ? 26 : 16),
      children: [
        PageHeader(
          eyebrow: 'Triage',
          title: 'Threat queue',
          subtitle: 'Operator events from your own server, with a recorded decision for each alert.',
          actions: [
            BusyButton(
              label: 'Refresh',
              busy: _loading,
              icon: Icons.refresh_rounded,
              filled: false,
              onPressed: () {
                _load();
                widget.state.refresh(silent: true);
              },
            ),
          ],
        ),
        const SizedBox(height: 20),
        if (_error != null) ...[
          ErrorBanner(message: _error!, onRetry: _load),
          const SizedBox(height: 16),
        ],
        CsCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  SizedBox(
                    width: 190,
                    child: DropdownButtonFormField<String>(
                      isExpanded: true,
                      initialValue: _severity,
                      decoration: const InputDecoration(labelText: 'Severity'),
                      dropdownColor: CsColors.card,
                      items: const [
                        DropdownMenuItem(value: 'all', child: Text('All severities')),
                        DropdownMenuItem(value: 'HIGH', child: Text('High')),
                        DropdownMenuItem(value: 'MEDIUM', child: Text('Medium')),
                        DropdownMenuItem(value: 'LOW', child: Text('Low')),
                      ],
                      onChanged: (value) {
                        setState(() => _severity = value ?? 'all');
                        _load();
                      },
                    ),
                  ),
                  SizedBox(
                    width: 200,
                    child: DropdownButtonFormField<String>(
                      isExpanded: true,
                      initialValue: _status,
                      decoration: const InputDecoration(labelText: 'Status'),
                      dropdownColor: CsColors.card,
                      items: const [
                        DropdownMenuItem(value: 'all', child: Text('All statuses')),
                        DropdownMenuItem(value: 'Open', child: Text('Open')),
                        DropdownMenuItem(value: 'Under review', child: Text('Under review')),
                        DropdownMenuItem(value: 'Contained (demo)', child: Text('Contained')),
                      ],
                      onChanged: (value) {
                        setState(() => _status = value ?? 'all');
                        _load();
                      },
                    ),
                  ),
                  if (filtered)
                    Padding(
                      padding: const EdgeInsets.only(top: 6),
                      child: TextButton.icon(
                        onPressed: () {
                          setState(() {
                            _severity = 'all';
                            _status = 'all';
                          });
                          _load();
                        },
                        icon: const Icon(Icons.filter_alt_off_outlined, size: 17),
                        label: const Text('Reset filters'),
                      ),
                    ),
                ],
              ),
              const SizedBox(height: 16),
              const Divider(),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: Text(
                      _loading
                          ? 'Loading the queue…'
                          : filtered
                              ? '$_total of $_allTotal events match these filters'
                              : '$_total event${_total == 1 ? '' : 's'} in the queue',
                      style: const TextStyle(color: CsColors.muted, fontSize: 12.5),
                    ),
                  ),
                ],
              ),
              if (_loading)
                const LoadingBlock(label: 'Loading events…')
              else if (_events.isEmpty)
                EmptyState(
                  icon: Icons.shield_outlined,
                  title: filtered ? 'No matching events' : 'No events received',
                  body: filtered
                      ? 'Nothing matches this filter combination. Try widening it.'
                      : 'The queue is empty. It only fills when an approved system posts events to this server.',
                )
              else
                ..._events.map((event) => _EventTile(event: event, onAction: (action) => _act(event, action))),
            ],
          ),
        ),
        const SizedBox(height: 16),
        const InfoNote(
          text: 'Containment records a label in the audit trail. It does not change device, account, or network state.',
          icon: Icons.info_outline_rounded,
        ),
      ],
    );
  }
}

class _EventTile extends StatelessWidget {
  const _EventTile({required this.event, required this.onAction});

  final EventItem event;
  final ValueChanged<String> onAction;

  @override
  Widget build(BuildContext context) {
    final color = severityColor(event.severity);
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
              Icon(Icons.warning_amber_rounded, color: color, size: 20),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      event.type.replaceAll('_', ' '),
                      style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      [
                        if (event.group.isNotEmpty) event.group,
                        if (event.source.isNotEmpty) event.source,
                        if (event.count > 0) '${event.count}×',
                        relativeTime(event.time),
                      ].join(' · '),
                      style: const TextStyle(color: CsColors.faint, fontSize: 11.5),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Pill(label: event.severity, color: color),
                  const SizedBox(height: 6),
                  Text(event.status, style: const TextStyle(color: CsColors.muted, fontSize: 11)),
                ],
              ),
            ],
          ),
          if (event.detail.isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(event.detail, style: const TextStyle(color: CsColors.muted, fontSize: 12.5, height: 1.4)),
          ],
          if (event.rule.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text('Rule: ${event.rule}', style: const TextStyle(color: CsColors.faint, fontSize: 11.5)),
          ],
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              OutlinedButton(
                onPressed: () => onAction('Investigate'),
                child: const Text('Investigate'),
              ),
              OutlinedButton(
                onPressed: () => onAction('Contain'),
                child: const Text('Contain'),
              ),
              OutlinedButton(
                onPressed: () => onAction('Reopen'),
                child: const Text('Reopen'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
