import 'package:flutter/foundation.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter/semantics.dart';

import 'app_state.dart';
import 'screens/auth_screen.dart';
import 'screens/shell.dart';
import 'theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  if (kIsWeb) {
    SemanticsBinding.instance.ensureSemantics();
  }
  runApp(const CampusShieldApp());
}

class CampusShieldApp extends StatefulWidget {
  const CampusShieldApp({super.key});

  @override
  State<CampusShieldApp> createState() => _CampusShieldAppState();
}

class _CampusShieldAppState extends State<CampusShieldApp> {
  late final AppState _state = AppState();

  @override
  void initState() {
    super.initState();
    _state.init();
  }

  @override
  void dispose() {
    _state.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CampusShield',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(),
      home: AnimatedBuilder(
        animation: _state,
        builder: (context, _) {
          if (_state.booting) return const BootScreen();
          return _state.signedIn
              ? Shell(state: _state)
              : AuthScreen(state: _state);
        },
      ),
    );
  }
}
