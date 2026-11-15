import 'package:material_ui/material_ui.dart';

class CsColors {
  static const bg = Color(0xFF070E1C);
  static const surface = Color(0xFF0C1730);
  static const card = Color(0xFF101D3A);
  static const cardAlt = Color(0xFF0E1A33);
  static const border = Color(0xFF1F3157);
  static const primary = Color(0xFF38BDF8);
  static const primaryDeep = Color(0xFF0E7490);
  static const green = Color(0xFF34D399);
  static const amber = Color(0xFFFBBF24);
  static const red = Color(0xFFF87171);
  static const text = Color(0xFFE9F1FF);
  static const muted = Color(0xFF9AAFCC);
  static const faint = Color(0xFF6B81A3);
}

ThemeData buildTheme() {
  final base = ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: CsColors.bg,
    colorScheme: const ColorScheme.dark(
      primary: CsColors.primary,
      onPrimary: Color(0xFF04121F),
      secondary: CsColors.green,
      surface: CsColors.surface,
      onSurface: CsColors.text,
      error: CsColors.red,
    ),
  );

  return base.copyWith(
    textTheme: base.textTheme.apply(
      bodyColor: CsColors.text,
      displayColor: CsColors.text,
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: Colors.transparent,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
    ),
    cardTheme: CardThemeData(
      color: CsColors.card,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(18),
        side: const BorderSide(color: CsColors.border),
      ),
    ),
    dividerTheme: const DividerThemeData(color: CsColors.border, thickness: 1),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: CsColors.cardAlt,
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: CsColors.border),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: CsColors.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: CsColors.primary),
      ),
      labelStyle: const TextStyle(color: CsColors.muted),
      hintStyle: const TextStyle(color: CsColors.faint),
    ),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: CsColors.card,
      contentTextStyle: const TextStyle(color: CsColors.text),
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: CsColors.primary,
        foregroundColor: const Color(0xFF04121F),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        textStyle: const TextStyle(fontWeight: FontWeight.w700),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: CsColors.text,
        side: const BorderSide(color: CsColors.border),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    ),
    switchTheme: SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.selected) ? CsColors.primary : CsColors.faint,
      ),
      trackColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.selected) ? CsColors.primaryDeep : CsColors.border,
      ),
    ),
    chipTheme: base.chipTheme.copyWith(
      backgroundColor: CsColors.cardAlt,
      side: const BorderSide(color: CsColors.border),
      labelStyle: const TextStyle(color: CsColors.muted, fontSize: 12),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(999)),
    ),
  );
}

Color severityColor(String severity) {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return CsColors.red;
    case 'MEDIUM':
      return CsColors.amber;
    case 'LOW':
      return CsColors.primary;
    default:
      return CsColors.muted;
  }
}

Color gradeColor(double? score) {
  if (score == null) return CsColors.muted;
  if (score >= 95) return CsColors.green;
  if (score >= 80) return CsColors.primary;
  if (score >= 60) return CsColors.amber;
  return CsColors.red;
}

Color statusColor(String status) {
  switch (status) {
    case 'pass':
      return CsColors.green;
    case 'warn':
    case 'fail':
      return CsColors.red;
    case 'info':
      return CsColors.primary;
    default:
      return CsColors.amber;
  }
}

String formatCount(int value) {
  if (value >= 1000000) return '${(value / 1000000).toStringAsFixed(1)}M';
  if (value >= 1000) return '${(value / 1000).toStringAsFixed(1)}k';
  return '$value';
}

String formatBytes(int bytes) {
  if (bytes >= 1 << 30) return '${(bytes / (1 << 30)).toStringAsFixed(1)} GB';
  if (bytes >= 1 << 20) return '${(bytes / (1 << 20)).toStringAsFixed(1)} MB';
  if (bytes >= 1 << 10) return '${(bytes / (1 << 10)).toStringAsFixed(1)} KB';
  return '$bytes B';
}

String _two(int value) => value.toString().padLeft(2, '0');

String formatDateTime(DateTime? value) {
  if (value == null) return 'Never';
  return '${value.year}-${_two(value.month)}-${_two(value.day)} ${_two(value.hour)}:${_two(value.minute)}';
}

String formatDate(DateTime? value) {
  if (value == null) return 'Never';
  return '${value.year}-${_two(value.month)}-${_two(value.day)}';
}

String relativeTime(DateTime? value) {
  if (value == null) return 'Never';
  final delta = DateTime.now().difference(value);
  if (delta.isNegative) {
    final ahead = value.difference(DateTime.now());
    if (ahead.inDays > 0) return 'in ${ahead.inDays} d';
    if (ahead.inHours > 0) return 'in ${ahead.inHours} h';
    return 'in ${ahead.inMinutes.clamp(1, 59)} min';
  }
  if (delta.inDays > 0) return '${delta.inDays} d ago';
  if (delta.inHours > 0) return '${delta.inHours} h ago';
  if (delta.inMinutes > 0) return '${delta.inMinutes} min ago';
  return 'just now';
}

String weekdayName(int index) {
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  return days[index.clamp(0, 6)];
}
