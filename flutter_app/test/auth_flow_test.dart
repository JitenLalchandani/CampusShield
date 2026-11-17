import 'dart:convert';
import 'dart:io';

import 'package:campusshield_app/api.dart';
import 'package:campusshield_app/app_state.dart';
import 'package:campusshield_app/screens/auth_screen.dart';
import 'package:campusshield_app/theme.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

String _fixture(String name) => File('test/fixtures/$name.json').readAsStringSync();

http.Response _json(String body, {int status = 200}) => http.Response.bytes(
      utf8.encode(body),
      status,
      headers: {'content-type': 'application/json; charset=utf-8'},
    );

http.Client _client({
  required String status,
  http.Response Function(http.Request request)? onSignup,
  http.Response Function(http.Request request)? onLogin,
  bool offline = false,
}) {
  final protection = _fixture('protection');
  final summary = _fixture('summary');
  final activity = _fixture('activity');
  final assistant = _fixture('assistant');

  return MockClient((request) async {
    if (offline) throw http.ClientException('offline');

    final path = request.url.path;
    if (path == '/api/auth/status') return _json(status);
    if (path == '/api/auth/signup' && onSignup != null) return onSignup(request);
    if (path == '/api/auth/login' && onLogin != null) return onLogin(request);
    if (path == '/api/protection') return _json(protection);
    if (path == '/api/summary') return _json(summary);
    if (path == '/api/activity') return _json(activity);
    if (path == '/api/assistant/suggest') return _json(assistant);
    return _json(jsonEncode({'error': 'not found'}), status: 404);
  });
}

const _noAccount = '{"hasAccount":false,"signupOpen":true,"user":null}';
const _hasAccount = '{"hasAccount":true,"signupOpen":false,"user":null}';

const _sessionBody = '{"user":{"id":"user-1","email":"owner@example.com",'
    '"name":"Meera Patel","role":"owner"},"token":"tok-123",'
    '"expiresAt":"2026-12-18T00:00:00.000Z"}';

Future<void> _pumpAuth(WidgetTester tester, AppState state) async {
  await tester.pumpWidget(
    MaterialApp(theme: buildTheme(), home: AuthScreen(state: state)),
  );
  await tester.pump();
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
  });

  testWidgets('asks for an account when the server has none', (tester) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final state = AppState(api: ApiClient(httpClient: _client(status: _noAccount)));
    addTearDown(state.dispose);
    await state.init();

    await _pumpAuth(tester, state);

    expect(find.text('Create your account'), findsOneWidget);
    expect(find.widgetWithText(FilledButton, 'Create account'), findsOneWidget);
    expect(find.text('Server address'), findsOneWidget);
    expect(find.textContaining('scrypt'), findsOneWidget);
    expect(state.signedIn, isFalse);
    expect(tester.takeException(), isNull);
  });

  testWidgets('offers sign-in when an account already exists', (tester) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final state = AppState(api: ApiClient(httpClient: _client(status: _hasAccount)));
    addTearDown(state.dispose);
    await state.init();

    await _pumpAuth(tester, state);

    expect(find.text('Sign in'), findsWidgets);
    expect(find.widgetWithText(FilledButton, 'Sign in'), findsOneWidget);
    expect(find.text('Create your account'), findsNothing);
  });

  testWidgets('creates the account, keeps the session, and loads real data', (tester) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    http.Request? signup;
    final state = AppState(
      api: ApiClient(
        httpClient: _client(
          status: _noAccount,
          onSignup: (request) {
            signup = request;
            return _json(_sessionBody, status: 201);
          },
        ),
      ),
    );
    addTearDown(state.dispose);
    await state.init();

    await _pumpAuth(tester, state);

    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Meera Patel');
    await tester.enterText(fields.at(1), 'owner@example.com');
    await tester.enterText(fields.at(2), 'correct horse battery');
    await tester.tap(find.widgetWithText(FilledButton, 'Create account'));
    await tester.pumpAndSettle();

    expect(signup, isNotNull);
    final body = jsonDecode(signup!.body) as Map<String, dynamic>;
    expect(body['name'], 'Meera Patel');
    expect(body['email'], 'owner@example.com');
    expect(body['password'], 'correct horse battery');

    expect(state.signedIn, isTrue);
    expect(state.user?.role, 'owner');
    expect(state.protection, isNotNull);
    expect(state.score.average, 90);

    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('campusshield.session'), 'tok-123');
  });

  testWidgets('blocks a short password before calling the server', (tester) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    var called = false;
    final state = AppState(
      api: ApiClient(
        httpClient: _client(
          status: _noAccount,
          onSignup: (_) {
            called = true;
            return _json(_sessionBody, status: 201);
          },
        ),
      ),
    );
    addTearDown(state.dispose);
    await state.init();

    await _pumpAuth(tester, state);

    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Meera Patel');
    await tester.enterText(fields.at(1), 'owner@example.com');
    await tester.enterText(fields.at(2), 'short');
    await tester.tap(find.widgetWithText(FilledButton, 'Create account'));
    await tester.pump();

    expect(called, isFalse);
    expect(find.textContaining('at least 10 characters'), findsOneWidget);
    expect(state.signedIn, isFalse);
  });

  testWidgets('shows the connection error and retries', (tester) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final state = AppState(api: ApiClient(httpClient: _client(status: _noAccount, offline: true)));
    addTearDown(state.dispose);
    await state.init();

    await _pumpAuth(tester, state);

    expect(find.textContaining('Cannot reach the CampusShield API'), findsOneWidget);
    expect(find.text('Retry connection'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('signs out by clearing the stored session', (tester) async {
    final state = AppState(
      api: ApiClient(
        httpClient: _client(
          status: _noAccount,
          onSignup: (_) => _json(_sessionBody, status: 201),
        ),
      ),
    );
    addTearDown(state.dispose);
    await state.init();

    await state.createAccount(
      name: 'Meera Patel',
      email: 'owner@example.com',
      password: 'correct horse battery',
      baseUrl: 'http://127.0.0.1:3999',
    );

    expect(state.signedIn, isTrue);
    await state.signOut();

    expect(state.signedIn, isFalse);
    expect(state.protection, isNull);
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('campusshield.session'), isNull);
  });
}
