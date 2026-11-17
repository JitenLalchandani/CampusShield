import 'package:material_ui/material_ui.dart';

import '../app_state.dart';
import '../theme.dart';
import 'activity_screen.dart';
import 'assistant_screen.dart';
import 'coverage_screen.dart';
import 'protection_screen.dart';
import 'settings_screen.dart';
import 'threats_screen.dart';

class Shell extends StatefulWidget {
  const Shell({super.key, required this.state});

  final AppState state;

  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  int _index = 0;
  bool _listening = false;

  @override
  void initState() {
    super.initState();
    widget.state.addListener(_onStateChanged);
    _listening = true;
  }

  @override
  void dispose() {
    if (_listening) widget.state.removeListener(_onStateChanged);
    super.dispose();
  }

  void _onStateChanged() {
    final message = widget.state.takeAlert();
    if (message == null || !mounted) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Row(
            children: [
              const Icon(Icons.shield_outlined, color: CsColors.red, size: 18),
              const SizedBox(width: 10),
              Expanded(child: Text(message)),
            ],
          ),
          duration: const Duration(seconds: 6),
        ),
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.state,
      builder: (context, _) {
        final width = MediaQuery.sizeOf(context).width;
        final wide = width >= 900;
        final body = _buildBody();

        if (widget.state.booting) {
          return const Scaffold(body: BootScreen());
        }

        if (wide) {
          return Scaffold(
            body: SafeArea(
              child: Row(
                children: [
                  NavigationRail(
                    backgroundColor: CsColors.surface,
                    selectedIndex: _index,
                    onDestinationSelected: (value) => setState(() => _index = value),
                    extended: width >= 1200,
                    minExtendedWidth: 210,
                    leading: const Padding(
                      padding: EdgeInsets.symmetric(vertical: 18, horizontal: 8),
                      child: _Brand(compact: false),
                    ),
                    trailing: Padding(
                      padding: const EdgeInsets.only(bottom: 18),
                      child: _ConnectionDot(state: widget.state),
                    ),
                    destinations: _destinations
                        .map((item) => NavigationRailDestination(
                              icon: Icon(item.icon),
                              selectedIcon: Icon(item.icon, color: CsColors.primary),
                              label: Text(item.label),
                            ))
                        .toList(),
                  ),
                  Expanded(
                    child: Column(
                      children: [
                        _TopBar(state: widget.state),
                        Expanded(child: body),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          );
        }

        return Scaffold(
          body: SafeArea(
            child: Column(
              children: [
                _TopBar(state: widget.state, compact: true),
                Expanded(child: body),
              ],
            ),
          ),
          bottomNavigationBar: NavigationBar(
            backgroundColor: CsColors.surface,
            indicatorColor: CsColors.primary.withValues(alpha: 0.16),
            selectedIndex: _index,
            height: 66,
            labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
            onDestinationSelected: (value) => setState(() => _index = value),
            destinations: _destinations
                .map((item) => NavigationDestination(icon: Icon(item.icon), label: item.label))
                .toList(),
          ),
        );
      },
    );
  }

  Widget _buildBody() {
    return IndexedStack(
      index: _index,
      children: [
        AssistantScreen(
          state: widget.state,
          onNavigate: (index) => setState(() => _index = index),
        ),
        ProtectionScreen(state: widget.state),
        ThreatsScreen(state: widget.state),
        ActivityScreen(state: widget.state),
        CoverageScreen(state: widget.state),
        SettingsScreen(state: widget.state),
      ],
    );
  }
}

class _Destination {
  const _Destination(this.label, this.icon);

  final String label;
  final IconData icon;
}

const _destinations = [
  _Destination('Assistant', Icons.auto_awesome_outlined),
  _Destination('Protection', Icons.shield_outlined),
  _Destination('Threats', Icons.warning_amber_rounded),
  _Destination('Activity', Icons.history_rounded),
  _Destination('Coverage', Icons.grid_view_rounded),
  _Destination('Settings', Icons.settings_outlined),
];

class BootScreen extends StatelessWidget {
  const BootScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: CsColors.bg,
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ClipRRect(
              borderRadius: BorderRadius.circular(20),
              child: Image.asset('assets/campusshield.png', width: 64, height: 64),
            ),
            const SizedBox(height: 18),
            const Text('CampusShield', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800)),
            const SizedBox(height: 18),
            const SizedBox(
              width: 22,
              height: 22,
              child: CircularProgressIndicator(strokeWidth: 2.2, color: CsColors.primary),
            ),
          ],
        ),
      ),
    );
  }
}

class _Brand extends StatelessWidget {
  const _Brand({this.compact = false});

  final bool compact;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        ClipRRect(
          borderRadius: BorderRadius.circular(10),
          child: Image.asset('assets/campusshield.png', width: 32, height: 32),
        ),
        if (!compact) ...[
          const SizedBox(width: 10),
          const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('CampusShield', style: TextStyle(fontWeight: FontWeight.w800, fontSize: 15)),
              Text('Cross-device safety', style: TextStyle(color: CsColors.faint, fontSize: 10.5)),
            ],
          ),
        ],
      ],
    );
  }
}

class _TopBar extends StatelessWidget {
  const _TopBar({required this.state, this.compact = false});

  final AppState state;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final score = state.score.average;
    return Container(
      padding: EdgeInsets.fromLTRB(compact ? 14 : 26, 12, compact ? 14 : 26, 10),
      decoration: const BoxDecoration(
        border: Border(bottom: BorderSide(color: CsColors.border)),
      ),
      child: Row(
        children: [
          if (compact)
            Flexible(
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const _Brand(compact: true),
                  const SizedBox(width: 10),
                  const Flexible(
                    child: Text(
                      'CampusShield',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(fontWeight: FontWeight.w800, fontSize: 15),
                    ),
                  ),
                ],
              ),
            ),
          const Spacer(),
          if (score != null) ...[
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
              decoration: BoxDecoration(
                color: gradeColor(score).withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(999),
                border: Border.all(color: gradeColor(score).withValues(alpha: 0.35)),
              ),
              child: Text(
                compact ? '${score.round()}' : '${score.round()} · ${state.score.grade}',
                style: TextStyle(color: gradeColor(score), fontSize: 11.5, fontWeight: FontWeight.w700),
              ),
            ),
            const SizedBox(width: 8),
          ],
          _ConnectionDot(state: state, showLabel: !compact),
          const SizedBox(width: 4),
          _AccountMenu(state: state),
          IconButton(
            tooltip: 'Refresh',
            onPressed: state.refreshing ? null : () => state.refresh(),
            icon: state.refreshing
                ? const SizedBox(
                    width: 17,
                    height: 17,
                    child: CircularProgressIndicator(strokeWidth: 2, color: CsColors.primary),
                  )
                : const Icon(Icons.refresh_rounded, color: CsColors.muted),
          ),
        ],
      ),
    );
  }
}

class _AccountMenu extends StatelessWidget {
  const _AccountMenu({required this.state});

  final AppState state;

  String _initials(String name) {
    final parts = name.trim().split(RegExp(r'\s+')).where((part) => part.isNotEmpty).toList();
    if (parts.isEmpty) return '?';
    if (parts.length == 1) return parts.first.substring(0, 1).toUpperCase();
    return (parts.first.substring(0, 1) + parts.last.substring(0, 1)).toUpperCase();
  }

  @override
  Widget build(BuildContext context) {
    final user = state.user;

    return PopupMenuButton<String>(
      tooltip: 'Account',
      offset: const Offset(0, 42),
      onSelected: (value) {
        if (value == 'signout') state.signOut();
      },
      itemBuilder: (context) => [
        PopupMenuItem<String>(
          enabled: false,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                user?.name ?? 'Account',
                style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13.5),
              ),
              const SizedBox(height: 2),
              Text(user?.email ?? '', style: const TextStyle(color: CsColors.muted, fontSize: 11.5)),
              const SizedBox(height: 2),
              Text(
                '${user?.roleLabel ?? ''} · ${state.apiBase.isEmpty ? 'this server' : state.apiBase}',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(color: CsColors.faint, fontSize: 11),
              ),
            ],
          ),
        ),
        const PopupMenuDivider(),
        const PopupMenuItem<String>(
          value: 'signout',
          child: Row(
            children: [
              Icon(Icons.logout_rounded, size: 18, color: CsColors.muted),
              SizedBox(width: 10),
              Text('Sign out'),
            ],
          ),
        ),
      ],
      child: CircleAvatar(
        radius: 15,
        backgroundColor: CsColors.primary.withValues(alpha: 0.16),
        child: Text(
          _initials(user?.name ?? ''),
          style: const TextStyle(color: CsColors.primary, fontSize: 12, fontWeight: FontWeight.w700),
        ),
      ),
    );
  }
}

class _ConnectionDot extends StatelessWidget {
  const _ConnectionDot({this.state, this.showLabel = true});

  final AppState? state;
  final bool showLabel;

  @override
  Widget build(BuildContext context) {
    final offline = state?.error != null;
    return Tooltip(
      message: offline ? 'API unreachable' : 'Connected',
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              color: offline ? CsColors.red : CsColors.green,
              shape: BoxShape.circle,
            ),
          ),
          if (state != null && showLabel) ...[
            const SizedBox(width: 6),
            Text(
              offline ? 'Offline' : 'Live',
              style: TextStyle(color: offline ? CsColors.red : CsColors.muted, fontSize: 11),
            ),
          ],
        ],
      ),
    );
  }
}
