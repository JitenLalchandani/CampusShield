import 'package:material_ui/material_ui.dart';

import '../api.dart';
import '../app_state.dart';
import '../theme.dart';
import '../widgets/common.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key, required this.state});

  final AppState state;

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  late final TextEditingController _server;
  final _name = TextEditingController();
  final _username = TextEditingController();
  final _email = TextEditingController();
  final _password = TextEditingController();

  late bool _creating;
  bool _busy = false;
  bool _obscure = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    final state = widget.state;
    _creating = state.signupOpen || !state.authStatus.hasAccount;
    _server = TextEditingController(
      text: state.apiBase.isEmpty ? state.api.baseUrl : state.apiBase,
    );
  }

  @override
  void dispose() {
    _server.dispose();
    _name.dispose();
    _username.dispose();
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_busy) return;

    final email = _email.text.trim();
    final password = _password.text;
    final name = _name.text.trim();
    final username = _username.text.trim();

    final problem = _creating
        ? (name.length < 2
            ? 'Enter your name.'
            : !RegExp(r'^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$').hasMatch(username)
                ? 'Choose a username of 3-32 letters, numbers, dots, dashes, or underscores.'
                : !email.contains('@')
                    ? 'Enter your email address.'
                    : password.length < 10
                        ? 'Use at least 10 characters for the password.'
                        : null)
        : (email.isEmpty || password.isEmpty ? 'Enter your email or username and password.' : null);

    if (problem != null) {
      setState(() => _error = problem);
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });

    try {
      if (_creating) {
        await widget.state.createAccount(
          name: name,
          username: username,
          email: email,
          password: password,
          baseUrl: _server.text,
        );
      } else {
        await widget.state.signIn(
          identifier: email,
          password: password,
          baseUrl: _server.text,
        );
      }
    } catch (caught) {
      if (!mounted) return;
      setState(() {
        _error = caught is ApiException ? caught.message : 'Could not reach the server.';
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _retry() async {
    setState(() => _busy = true);
    await widget.state.checkAuth();
    if (!mounted) return;
    setState(() {
      _busy = false;
      _creating = widget.state.signupOpen || !widget.state.authStatus.hasAccount;
      _error = widget.state.error;
    });
  }

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= 980;

    return Scaffold(
      body: Container(
        color: CsColors.bg,
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 980),
                child: wide
                    ? Row(
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          const Expanded(child: _Pitch()),
                          const SizedBox(width: 40),
                          SizedBox(width: 420, child: _form()),
                        ],
                      )
                    : Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const _BrandMark(),
                          const SizedBox(height: 22),
                          _form(),
                        ],
                      ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _form() {
    final state = widget.state;
    final connectionError = _error ?? (state.error != null && state.signedIn == false ? state.error : null);

    return CsCard(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (!wideForContext())
            const Text(
              'CampusShield',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
            ),
          if (!wideForContext()) const SizedBox(height: 4),
          Text(
            _creating ? 'Create your account' : 'Sign in',
            style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w800, height: 1.15),
          ),
          const SizedBox(height: 8),
          Text(
            _creating
                ? 'The first account on this server becomes the owner. Your data stays on the server you point to below.'
                : 'Use the account that was created on this server.',
            style: const TextStyle(color: CsColors.muted, fontSize: 13, height: 1.45),
          ),
          const SizedBox(height: 20),
          if (_creating) ...[
            TextField(
              controller: _name,
              textInputAction: TextInputAction.next,
              decoration: const InputDecoration(labelText: 'Name', hintText: 'Meera Patel'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _username,
              autocorrect: false,
              textInputAction: TextInputAction.next,
              decoration: const InputDecoration(
                labelText: 'Username',
                hintText: 'meera.patel',
                helperText: '3-32 letters, numbers, dots, dashes, or underscores. You can sign in with this too.',
              ),
            ),
            const SizedBox(height: 12),
          ],
          TextField(
            controller: _email,
            keyboardType: _creating ? TextInputType.emailAddress : TextInputType.text,
            autocorrect: false,
            textInputAction: TextInputAction.next,
            decoration: InputDecoration(
              labelText: _creating ? 'Email' : 'Email or username',
              hintText: _creating ? 'you@campus.edu' : 'you@campus.edu or meera.patel',
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _password,
            obscureText: _obscure,
            onSubmitted: (_) => _submit(),
            decoration: InputDecoration(
              labelText: 'Password',
              helperText: _creating ? 'At least 10 characters. A short sentence works.' : null,
              suffixIcon: IconButton(
                tooltip: _obscure ? 'Show password' : 'Hide password',
                onPressed: () => setState(() => _obscure = !_obscure),
                icon: Icon(
                  _obscure ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                  color: CsColors.muted,
                  size: 20,
                ),
              ),
            ),
          ),
          const SizedBox(height: 16),
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            childrenPadding: const EdgeInsets.only(bottom: 8),
            title: const Text('Server address', style: TextStyle(fontSize: 13.5, fontWeight: FontWeight.w600)),
            subtitle: Text(
              _server.text.trim().isEmpty ? 'Uses this page’s origin' : _server.text.trim(),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: CsColors.faint, fontSize: 12),
            ),
            children: [
              TextField(
                controller: _server,
                keyboardType: TextInputType.url,
                autocorrect: false,
                onChanged: (_) => setState(() {}),
                decoration: const InputDecoration(
                  labelText: 'CampusShield server',
                  hintText: 'http://127.0.0.1:3999',
                ),
              ),
            ],
          ),
          if (connectionError != null) ...[
            const SizedBox(height: 4),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: CsColors.red.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: CsColors.red.withValues(alpha: 0.35)),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.error_outline, color: CsColors.red, size: 18),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      connectionError,
                      style: const TextStyle(color: CsColors.red, fontSize: 12.5, height: 1.4),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            TextButton.icon(
              onPressed: _busy ? null : _retry,
              icon: const Icon(Icons.refresh_rounded, size: 18),
              label: const Text('Retry connection'),
            ),
          ],
          const SizedBox(height: 8),
          SizedBox(
            width: double.infinity,
            child: FilledButton(
              onPressed: _busy ? null : _submit,
              child: _busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF04121F)),
                    )
                  : Text(_creating ? 'Create account' : 'Sign in'),
            ),
          ),
          const SizedBox(height: 14),
          const Text(
            'Passwords are hashed with scrypt on your server. Device checks are read-only, and scan '
            'results are recorded, not simulated.',
            style: TextStyle(color: CsColors.faint, fontSize: 11.5, height: 1.45),
          ),
        ],
      ),
    );
  }

  bool wideForContext() => MediaQuery.sizeOf(context).width >= 980;
}

class _BrandMark extends StatelessWidget {
  const _BrandMark();

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        ClipRRect(
          borderRadius: BorderRadius.circular(14),
          child: Image.asset('assets/campusshield.png', width: 44, height: 44),
        ),
        const SizedBox(width: 12),
        const Flexible(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text('CampusShield', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800)),
              Text(
                'Security tests that report real results',
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: CsColors.muted, fontSize: 12),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _Pitch extends StatelessWidget {
  const _Pitch();

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        const _BrandMark(),
        const SizedBox(height: 28),
        const Text(
          'Sign in, see what needs attention,\nand run a real security test.',
          style: TextStyle(fontSize: 30, fontWeight: FontWeight.w800, height: 1.18),
        ),
        const SizedBox(height: 16),
        const Text(
          'CampusShield checks the device it runs on, scans files with signatures and heuristics, '
          'quarantines what it flags, and explains the results. Scores and detections come from those '
          'checks, never from a demo dataset.',
          style: TextStyle(color: CsColors.muted, fontSize: 14, height: 1.55),
        ),
        const SizedBox(height: 26),
        const _Point(
          icon: Icons.verified_user_outlined,
          text: 'Accounts and scan history live on your own server.',
        ),
        const _Point(
          icon: Icons.travel_explore_rounded,
          text: 'AI suggestions need your OpenAI-compatible endpoint; the key stays on this device.',
        ),
        const _Point(
          icon: Icons.rule_folder_outlined,
          text: 'Threats are flagged by local rules, then explained, never invented.',
        ),
        const SizedBox(height: 10),
        const Text(
          'Device posture checks are available on macOS and Windows. File scanning runs where the '
          'server can read files; mobile shells link to the same server.',
          style: TextStyle(color: CsColors.faint, fontSize: 12, height: 1.5),
        ),
      ],
    );
  }
}

class _Point extends StatelessWidget {
  const _Point({required this.icon, required this.text});

  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 19, color: CsColors.primary),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: const TextStyle(color: CsColors.muted, fontSize: 13, height: 1.45),
            ),
          ),
        ],
      ),
    );
  }
}
