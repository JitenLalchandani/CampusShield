import 'dart:convert';
import 'dart:io';

import 'package:campusshield_app/api.dart';
import 'package:campusshield_app/app_state.dart';
import 'package:campusshield_app/screens/shell.dart';
import 'package:campusshield_app/theme.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

String _fixture(String name) => File('test/fixtures/$name.json').readAsStringSync();

const _authStatus = '{"hasAccount":true,"signupOpen":false,'
    '"user":{"id":"user-1","email":"owner@example.com","name":"Meera Patel","role":"owner"}}';

http.Client _fixtureClient() {
  final protection = _fixture('protection');
  final summary = _fixture('summary');
  final activity = _fixture('activity');
  final assistant = _fixture('assistant');
  return MockClient((request) async {
    final path = request.url.path;
    if (path == '/api/auth/status') return _json(_authStatus);
    if (path == '/api/protection') return _json(protection);
    if (path == '/api/summary') return _json(summary);
    if (path == '/api/activity') return _json(activity);
    if (path == '/api/assistant/suggest') return _json(assistant);
    return _json(jsonEncode({'error': 'not found'}), status: 404);
  });
}

http.Response _json(String body, {int status = 200}) => http.Response.bytes(
      utf8.encode(body),
      status,
      headers: {'content-type': 'application/json; charset=utf-8'},
    );

Future<AppState> _loadedState() async {
  final state = AppState(api: ApiClient(httpClient: _fixtureClient()));
  await state.init();
  return state;
}

void _sizeSurface(WidgetTester tester, Size size) {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.reset);
}

Future<void> _pumpShell(WidgetTester tester, AppState state) async {
  await tester.pumpWidget(
    MaterialApp(theme: buildTheme(), home: Shell(state: state)),
  );
  await tester.pump();
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
  });

  testWidgets('opens on the assistant with grounded recommendations', (tester) async {
    _sizeSurface(tester, const Size(1280, 900));
    final state = await _loadedState();
    addTearDown(state.dispose);

    await tester.pumpWidget(
      MaterialApp(theme: buildTheme(), home: Shell(state: state)),
    );
    await tester.pumpAndSettle();

    expect(find.text('Ask, then verify'), findsOneWidget);
    expect(find.text('Security test'), findsOneWidget);
    expect(find.text('Quarantine invoice.scr'), findsOneWidget);
    expect(find.text('AI suggestions need an endpoint'), findsOneWidget);
    expect(find.text('MP'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('renders the protection dashboard from live API payloads', (tester) async {
    _sizeSurface(tester, const Size(1280, 900));
    final state = await _loadedState();
    addTearDown(state.dispose);

    await _pumpShell(tester, state);

    await tester.tap(find.byIcon(Icons.shield_outlined).first);
    await tester.pump(const Duration(milliseconds: 50));

    expect(find.text('Device safety'), findsOneWidget);
    expect(find.text('Scanner ready'), findsOneWidget);
    expect(find.text('1 of 1'), findsOneWidget);
    expect(find.text('Meets-MacBook-Pro (90)'), findsOneWidget);
    expect(find.text('Live'), findsWidgets);
    expect(find.text('90 · Good'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('switches to the threats and activity destinations', (tester) async {
    _sizeSurface(tester, const Size(1280, 900));
    final state = await _loadedState();
    addTearDown(state.dispose);
    await _pumpShell(tester, state);

    await tester.tap(find.text('Threats'));
    await tester.pump(const Duration(milliseconds: 50));
    expect(find.text('Threat queue'), findsOneWidget);

    await tester.tap(find.text('Activity'));
    await tester.pump(const Duration(milliseconds: 50));
    expect(find.text('Activity'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('renders the compact phone layout with bottom navigation', (tester) async {
    _sizeSurface(tester, const Size(410, 860));
    final state = await _loadedState();
    addTearDown(state.dispose);

    await _pumpShell(tester, state);

    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.text('CampusShield'), findsOneWidget);
    expect(find.text('Ask, then verify'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('shows a reachable-server error instead of guessing', (tester) async {
    _sizeSurface(tester, const Size(1280, 900));
    final state = AppState(
      api: ApiClient(
        httpClient: MockClient((_) async => throw http.ClientException('offline')),
      ),
    );
    addTearDown(state.dispose);
    await state.init();

    await _pumpShell(tester, state);

    expect(find.textContaining('Cannot reach the CampusShield API'), findsWidgets);
    expect(find.text('Offline'), findsWidgets);

    await tester.tap(find.byIcon(Icons.shield_outlined).first);
    await tester.pump(const Duration(milliseconds: 50));
    expect(find.text('Loading the cross-device score…'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
