import 'package:material_ui/material_ui.dart';

import '../api.dart';
import '../app_state.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/common.dart';

class AssistantScreen extends StatefulWidget {
  const AssistantScreen({
    super.key,
    required this.state,
    required this.onNavigate,
  });

  final AppState state;
  final void Function(int index) onNavigate;

  @override
  State<AssistantScreen> createState() => _AssistantScreenState();
}

class _ChatMessage {
  const _ChatMessage(this.role, this.text);

  final String role;
  final String text;

  bool get isUser => role == 'user';
}

class _AssistantScreenState extends State<AssistantScreen> {
  final _chat = TextEditingController();
  final List<_ChatMessage> _messages = [];

  AssistantSuggestion? _suggestion;
  bool _loading = true;
  String? _loadError;

  AssistantTestResult? _test;
  bool _testing = false;
  String? _testError;
  String? _summary;
  String? _summaryForScan;
  bool _summaryLoading = false;

  String? _acting;
  bool _sending = false;

  @override
  void initState() {
    super.initState();
    _loadSuggestions();
  }

  @override
  void dispose() {
    _chat.dispose();
    super.dispose();
  }

  Future<void> _loadSuggestions({bool silent = false}) async {
    if (!silent) {
      setState(() {
        _loading = true;
        _loadError = null;
      });
    }

    try {
      final suggestion = await widget.state.assistantSuggestions();
      if (!mounted) return;
      setState(() {
        _suggestion = suggestion;
        _loading = false;
        _loadError = null;
      });
    } catch (caught) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _loadError = caught is ApiException ? caught.message : 'Could not build recommendations.';
      });
    }
  }

  Future<void> _runTest() async {
    if (_testing) return;

    setState(() {
      _testing = true;
      _testError = null;
      _summary = null;
      _summaryForScan = null;
    });

    try {
      final result = await widget.state.runSecurityTest();
      if (!mounted) return;
      setState(() {
        _test = result;
        _testing = false;
      });
      await _loadSuggestions(silent: true);
    } catch (caught) {
      if (!mounted) return;
      setState(() {
        _testing = false;
        _testError = caught is ApiException ? caught.message : 'The security test could not run.';
      });
    }
  }

  ScanRecord? get _testScan {
    final id = _test?.scan?.id;
    if (id == null || id.isEmpty) return null;

    for (final scan in widget.state.scans) {
      if (scan.id == id) return scan;
    }

    return _test?.scan;
  }

  void _maybeLoadSummary() {
    final scan = _testScan;
    if (scan == null || scan.isRunning) return;
    if (_summaryForScan == scan.id || _summaryLoading) return;

    _summaryLoading = true;
    _summaryForScan = scan.id;

    () async {
      try {
        final summary = await widget.state.assistantRunSummary();
        if (mounted) setState(() => _summary = summary);
      } catch (_) {
        if (mounted) setState(() => _summaryForScan = null);
      } finally {
        _summaryLoading = false;
      }
    }();
  }

  Future<void> _act(AssistantRecommendation rec) async {
    if (_acting != null) return;

    final action = rec.action;
    if (action.kind == 'open-protection') {
      widget.onNavigate(1);
      return;
    }
    if (action.kind == 'open-settings' || action.kind == 'schedule-scan') {
      widget.onNavigate(5);
      return;
    }

    setState(() => _acting = rec.id);

    try {
      switch (action.kind) {
        case 'run-check':
          await widget.state.checkDevice();
        case 'run-scan':
          await widget.state.runScan('quick');
        case 'quarantine-threat':
          await widget.state.quarantineById(action.scanId, action.threatId);
        case 'enable-watch':
          await widget.state.api.setWatch(true);
          await widget.state.refresh();
        default:
          break;
      }

      await _loadSuggestions(silent: true);
    } catch (caught) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(caught is ApiException ? caught.message : 'That action failed.')),
        );
      }
    } finally {
      if (mounted) setState(() => _acting = null);
    }
  }

  Future<void> _send([String? preset]) async {
    if (_sending) return;

    final message = (preset ?? _chat.text).trim();
    if (message.isEmpty) return;

    final history = _messages
        .where((item) => item.text.trim().isNotEmpty)
        .map((item) => {'role': item.role, 'content': item.text})
        .toList();

    setState(() {
      _sending = true;
      _messages.add(_ChatMessage('user', message));
      _chat.clear();
    });

    try {
      final reply = await widget.state.askAssistant(message, history: history);
      if (!mounted) return;

      setState(() {
        _messages.add(_ChatMessage('assistant', reply.reply));
        if (reply.run != null) {
          _test = reply.run;
          _summary = null;
          _summaryForScan = null;
        }
      });

      if (reply.recommendations.isNotEmpty) {
        setState(() {
          _suggestion = AssistantSuggestion(
            generatedAt: _suggestion?.generatedAt,
            recommendations: reply.recommendations,
            ai: reply.ai,
            aiSetup: _suggestion?.aiSetup,
          );
        });
      }
    } catch (caught) {
      if (!mounted) return;
      setState(() {
        _messages.add(_ChatMessage(
          'assistant',
          caught is ApiException ? caught.message : 'The assistant could not answer.',
        ));
      });
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    _maybeLoadSummary();

    return ListView(
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 32),
      children: [
        PageHeader(
          eyebrow: 'Assistant',
          title: 'Ask, then verify',
          subtitle:
              'Suggestions come from stored checks and scans. Run the security test to refresh them with '
              'real results from this server.',
          actions: [
            OutlinedButton.icon(
              onPressed: _loading ? null : () => _loadSuggestions(),
              icon: const Icon(Icons.refresh_rounded, size: 18),
              label: const Text('Refresh'),
            ),
          ],
        ),
        const SizedBox(height: 18),
        _testCard(),
        const SizedBox(height: 18),
        _aiCard(),
        const SizedBox(height: 18),
        _recommendationCard(),
        const SizedBox(height: 18),
        _chatCard(),
      ],
    );
  }

  Widget _testCard() {
    final scan = _testScan;
    final test = _test;

    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: CsColors.primary.withValues(alpha: 0.14),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Icon(Icons.security_rounded, color: CsColors.primary),
              ),
              const SizedBox(width: 12),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Security test', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
                    SizedBox(height: 3),
                    Text(
                      'A read-only device check plus a quick file scan, run now on the server host.',
                      style: TextStyle(color: CsColors.muted, fontSize: 12.5, height: 1.4),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              FilledButton.icon(
                onPressed: _testing || widget.state.activeScan != null ? null : _runTest,
                icon: _testing
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF04121F)),
                      )
                    : const Icon(Icons.play_arrow_rounded, size: 20),
                label: Text(_testing ? 'Running checks…' : test == null ? 'Run security test' : 'Run again'),
              ),
              if (widget.state.activeScan != null)
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 10),
                  child: Text(
                    'A scan is already running (${widget.state.activeScan!.filesScanned} files).',
                    style: const TextStyle(color: CsColors.muted, fontSize: 12),
                  ),
                ),
            ],
          ),
          if (_testError != null) ...[
            const SizedBox(height: 12),
            Text(_testError!, style: const TextStyle(color: CsColors.red, fontSize: 12.5)),
          ],
          if (test != null) ...[
            const SizedBox(height: 16),
            const Divider(height: 1),
            const SizedBox(height: 14),
            if (test.device != null) ...[
              Wrap(
                spacing: 8,
                runSpacing: 8,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  Text(
                    test.device!.name,
                    style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
                  ),
                  if (test.device!.score != null)
                    Pill(
                      label: '${test.device!.score!.round()} / 100 · ${test.device!.grade}',
                      color: gradeColor(test.device!.score!),
                    ),
                  const Pill(label: 'Device check', color: CsColors.primary, icon: Icons.desktop_windows_outlined),
                ],
              ),
              const SizedBox(height: 8),
            ] else if (test.checkMessage != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(
                  test.checkMessage!,
                  style: const TextStyle(color: CsColors.muted, fontSize: 12.5, height: 1.4),
                ),
              ),
            if (test.scanError != null)
              Text(test.scanError!, style: const TextStyle(color: CsColors.amber, fontSize: 12.5)),
            if (scan != null) ...[
              Row(
                children: [
                  Icon(
                    scan.isRunning ? Icons.search_rounded : Icons.fact_check_outlined,
                    size: 17,
                    color: scan.isRunning ? CsColors.primary : CsColors.green,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      scan.isRunning
                          ? 'Quick scan running · ${scan.filesScanned} files so far'
                          : 'Quick scan ${scan.status} · ${scan.filesScanned} files · '
                              '${scan.threatCount} detection(s)',
                      style: const TextStyle(fontSize: 12.5),
                    ),
                  ),
                ],
              ),
              if (scan.isRunning) ...[
                const SizedBox(height: 10),
                const LinearProgressIndicator(minHeight: 4),
              ],
              if (!scan.isRunning && scan.threatCount > 0) ...[
                const SizedBox(height: 8),
                TextButton.icon(
                  onPressed: () => widget.onNavigate(2),
                  icon: const Icon(Icons.warning_amber_rounded, size: 18, color: CsColors.amber),
                  label: Text(
                    'Review ${scan.threatCount} detection(s)',
                    style: const TextStyle(color: CsColors.amber),
                  ),
                ),
              ],
            ],
            if (_summary != null && _summary!.isNotEmpty) ...[
              const SizedBox(height: 10),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: CsColors.cardAlt,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: CsColors.border),
                ),
                child: Text(
                  _summary!,
                  style: const TextStyle(fontSize: 12.5, height: 1.5, color: CsColors.muted),
                ),
              ),
            ] else if (test.summary.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(
                  test.summary,
                  style: const TextStyle(fontSize: 12.5, height: 1.5, color: CsColors.muted),
                ),
              ),
          ],
        ],
      ),
    );
  }

  Widget _aiCard() {
    final suggestion = _suggestion;
    final ai = suggestion?.ai ?? AssistantAi.none;
    final configured = widget.state.ai.isConfigured;

    if (!configured) {
      return CsCard(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Icon(Icons.auto_awesome_outlined, color: CsColors.primary, size: 22),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('AI suggestions need an endpoint', style: TextStyle(fontWeight: FontWeight.w700)),
                  const SizedBox(height: 4),
                  Text(
                    suggestion?.aiSetup ??
                        'Connect an OpenAI-compatible endpoint in Settings. Until then, the next steps below '
                            'come directly from your checks and scans.',
                    style: const TextStyle(color: CsColors.muted, fontSize: 12.5, height: 1.45),
                  ),
                  const SizedBox(height: 8),
                  TextButton.icon(
                    onPressed: () => widget.onNavigate(5),
                    icon: const Icon(Icons.tune_rounded, size: 18),
                    label: const Text('Open AI settings'),
                  ),
                ],
              ),
            ),
          ],
        ),
      );
    }

    if (ai.reply.isEmpty && ai.error.isEmpty) {
      return const SizedBox.shrink();
    }

    return CsCard(
      padding: const EdgeInsets.all(16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.auto_awesome_rounded, color: CsColors.primary, size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'AI suggestion',
                  style: TextStyle(fontWeight: FontWeight.w700, fontSize: 13.5),
                ),
                const SizedBox(height: 6),
                Text(
                  ai.error.isEmpty ? ai.reply : 'The AI endpoint did not answer: ${ai.error}',
                  style: TextStyle(
                    color: ai.error.isEmpty ? CsColors.text : CsColors.amber,
                    fontSize: 12.5,
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  ai.disclaimer,
                  style: const TextStyle(color: CsColors.faint, fontSize: 11, height: 1.4),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _recommendationCard() {
    final suggestion = _suggestion;

    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionTitle(
            title: 'Recommended next steps',
            caption: suggestion == null
                ? 'Built from stored checks and scans.'
                : 'Built from stored checks and scans · ${_timeLabel(suggestion.generatedAt)}',
            trailing: _loading
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2, color: CsColors.primary),
                  )
                : null,
          ),
          const SizedBox(height: 14),
          if (_loadError != null)
            Text(_loadError!, style: const TextStyle(color: CsColors.red, fontSize: 12.5))
          else if (suggestion == null || suggestion.recommendations.isEmpty)
            Text(
              _loading ? 'Reading stored checks…' : 'No outstanding items. Run a security test to refresh the picture.',
              style: const TextStyle(color: CsColors.muted, fontSize: 12.5),
            )
          else
            ...suggestion.recommendations.map(_recommendationTile),
        ],
      ),
    );
  }

  Widget _recommendationTile(AssistantRecommendation rec) {
    final color = _severityColor(rec.severity);
    final busy = _acting == rec.id;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: CsColors.cardAlt,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: CsColors.border),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  margin: const EdgeInsets.only(top: 3),
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(color: color, shape: BoxShape.circle),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    rec.title,
                    style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13.5, height: 1.35),
                  ),
                ),
                const SizedBox(width: 8),
                Pill(label: rec.severity.toUpperCase(), color: color),
              ],
            ),
            if (rec.detail.isNotEmpty) ...[
              const SizedBox(height: 6),
              Padding(
                padding: const EdgeInsets.only(left: 18),
                child: Text(
                  rec.detail,
                  style: const TextStyle(color: CsColors.muted, fontSize: 12.3, height: 1.45),
                ),
              ),
            ],
            const SizedBox(height: 6),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton(
                onPressed: busy || _acting != null ? null : () => _act(rec),
                child: busy
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2, color: CsColors.primary),
                      )
                    : Text(_actionLabel(rec.action.kind)),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _chatCard() {
    return CsCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionTitle(
            title: 'Ask CampusShield',
            caption:
                'Answers use the same stored results. Ask for a security test and it runs the real checks.',
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              ActionChip(
                avatar: const Icon(Icons.security_rounded, size: 16, color: CsColors.primary),
                label: const Text('Run a security test'),
                onPressed: _sending || _testing ? null : _runTest,
              ),
              ActionChip(
                avatar: const Icon(Icons.monitor_heart_outlined, size: 16, color: CsColors.primary),
                label: const Text('What is my status?'),
                onPressed: _sending ? null : () => _send('What is my status?'),
              ),
              ActionChip(
                avatar: const Icon(Icons.warning_amber_rounded, size: 16, color: CsColors.primary),
                label: const Text('Any threats?'),
                onPressed: _sending ? null : () => _send('Are there any threats?'),
              ),
            ],
          ),
          if (_messages.isNotEmpty) ...[
            const SizedBox(height: 14),
            ..._messages.map(_bubble),
          ],
          if (_sending) ...[
            const SizedBox(height: 10),
            const Row(
              children: [
                SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2)),
                SizedBox(width: 10),
                Text('Checking stored results…', style: TextStyle(color: CsColors.muted, fontSize: 12)),
              ],
            ),
          ],
          const SizedBox(height: 12),
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Expanded(
                child: TextField(
                  controller: _chat,
                  minLines: 1,
                  maxLines: 3,
                  textInputAction: TextInputAction.send,
                  onSubmitted: (_) => _send(),
                  decoration: const InputDecoration(
                    hintText: 'Ask about your score, threats, or run a test…',
                  ),
                ),
              ),
              const SizedBox(width: 8),
              IconButton.filled(
                tooltip: 'Send',
                onPressed: _sending ? null : () => _send(),
                icon: const Icon(Icons.send_rounded, size: 19),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _bubble(_ChatMessage message) {
    final user = message.isUser;

    return Align(
      alignment: user ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: const BoxConstraints(maxWidth: 560),
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          color: user ? CsColors.primaryDeep.withValues(alpha: 0.35) : CsColors.cardAlt,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: user ? CsColors.primary.withValues(alpha: 0.35) : CsColors.border),
        ),
        child: Text(
          message.text,
          style: const TextStyle(fontSize: 12.8, height: 1.5),
        ),
      ),
    );
  }

  String _timeLabel(DateTime? time) {
    if (time == null) return 'just now';
    final local = time.toLocal();
    final minutes = local.minute.toString().padLeft(2, '0');
    return '${local.hour}:$minutes';
  }

  String _actionLabel(String kind) {
    switch (kind) {
      case 'run-check':
        return 'Run check';
      case 'run-scan':
        return 'Scan now';
      case 'quarantine-threat':
        return 'Quarantine';
      case 'enable-watch':
        return 'Turn on';
      case 'schedule-scan':
      case 'open-settings':
        return 'Open settings';
      case 'open-protection':
        return 'Open protection';
      default:
        return 'Open';
    }
  }

  Color _severityColor(String severity) {
    switch (severity.toUpperCase()) {
      case 'HIGH':
      case 'CRITICAL':
        return CsColors.red;
      case 'MEDIUM':
        return CsColors.amber;
      case 'LOW':
        return CsColors.primary;
      default:
        return CsColors.muted;
    }
  }
}
