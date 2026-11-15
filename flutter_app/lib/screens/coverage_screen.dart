import 'package:material_ui/material_ui.dart';

import '../app_state.dart';
import '../theme.dart';
import '../widgets/common.dart';

class CoverageScreen extends StatelessWidget {
  const CoverageScreen({super.key, required this.state});

  final AppState state;

  static const _rows = [
    _CoverageRow('Read-only device audit', true, false, false, true),
    _CoverageRow('File scanning (quick / full / custom)', true, false, false, true),
    _CoverageRow('Quarantine and restore', true, false, false, true),
    _CoverageRow('Real-time folder watch (user space)', true, false, false, true),
    _CoverageRow('Scheduled scans and exclusions', true, false, false, true),
    _CoverageRow('Cross-device safety score', true, true, true, true),
    _CoverageRow('Threat queue (needs your server)', true, true, true, true),
    _CoverageRow('AI explanation (optional endpoint)', true, true, true, true),
    _CoverageRow('Link inspector and password check', true, true, true, true),
  ];

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= 720;
    final protection = state.protection;

    return ListView(
      padding: EdgeInsets.all(wide ? 26 : 16),
      children: [
        const PageHeader(
          eyebrow: 'Coverage',
          title: 'What this build can and cannot do',
          subtitle: 'A capability map for the API this app is connected to. It never turns an unknown into a pass.',
        ),
        const SizedBox(height: 20),
        CsCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SectionTitle(
                title: 'Connected server',
                caption: protection == null
                    ? 'No server data loaded yet.'
                    : '${protection.platformLabel} · ${protection.storage}',
                trailing: Pill(
                  label: protection == null ? 'Offline' : 'Connected',
                  color: protection == null ? CsColors.red : CsColors.green,
                ),
              ),
              const SizedBox(height: 14),
              KeyValueRow(label: 'API URL', value: state.api.baseUrl),
              if (protection != null) ...[
                KeyValueRow(label: 'Scanner', value: protection.scanner.available ? 'Available' : 'Not available on this host'),
                KeyValueRow(label: 'Device audit', value: protection.devices.isEmpty ? 'No host check yet' : 'Available on this host'),
                KeyValueRow(label: 'Signature set', value: '${protection.scanner.signatureVersion} · ${protection.scanner.signatureCount} hashes'),
              ],
            ],
          ),
        ),
        const SizedBox(height: 16),
        CsCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SectionTitle(
                title: 'Platform coverage',
                caption: 'A check that a platform does not support is shown as unavailable, never guessed.',
              ),
              const SizedBox(height: 16),
              const _CoverageHeader(),
              const Divider(height: 24),
              ..._rows.map((row) => _CoverageLine(row: row)),
              const SizedBox(height: 8),
              const Text(
                'iOS and the Mac App Store sandbox cannot scan other apps’ files. Android and iOS build shells link '
                'into the shared score but do not run a host scan in this release.',
                style: TextStyle(color: CsColors.faint, fontSize: 11.5, height: 1.45),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        const CsCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SectionTitle(
                title: 'Scoring rules',
                caption: 'The same weights apply to posture findings and open malware findings.',
              ),
              SizedBox(height: 14),
              KeyValueRow(label: 'Start at', value: '100 points'),
              KeyValueRow(label: 'Critical', value: '−30 · High −18 · Medium −10 · Low −4'),
              KeyValueRow(label: 'Malware cap', value: '45 points per device, deduplicated by path'),
              KeyValueRow(label: 'Grades', value: 'Protected 95+ · Good 80+ · Needs attention 60+ · At risk <60'),
              SizedBox(height: 8),
              Text(
                'Quarantining or deleting a file removes its penalty. Unverified checks cost nothing but stay visible.',
                style: TextStyle(color: CsColors.faint, fontSize: 11.5, height: 1.45),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        const CsCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SectionTitle(
                title: 'Privacy',
                caption: 'Local-first by default. Nothing is sent to the developer.',
              ),
              SizedBox(height: 14),
              _Bullet('File contents are never uploaded. The scanner reads names, a 64 KB header, and a SHA-256 hash locally.'),
              _Bullet('Scans, findings, quarantine records, and settings stay in the local store or your own MongoDB.'),
              _Bullet('The AI assistant sends data only when you press Explain or Summary, and only to the endpoint you configure.'),
              _Bullet('The API key stays in this app’s local storage. Remote AI endpoints must use HTTPS.'),
              _Bullet('No accounts, ads, analytics, or developer telemetry.'),
            ],
          ),
        ),
        const SizedBox(height: 16),
        const InfoNote(
          text: 'Limits: the real-time watch cannot block execution, the signature set is small, and scheduled scans run '
              'only while the server process is open. A clean scan is not a guarantee that a file is safe.',
          icon: Icons.gpp_maybe_outlined,
          tone: CsColors.amber,
        ),
      ],
    );
  }
}

class _CoverageRow {
  const _CoverageRow(this.label, this.mac, this.mobile, this.mas, this.windows);

  final String label;
  final bool mac;
  final bool mobile;
  final bool mas;
  final bool windows;
}

class _CoverageHeader extends StatelessWidget {
  const _CoverageHeader();

  @override
  Widget build(BuildContext context) {
    return const Row(
      children: [
        Expanded(flex: 5, child: Text('Capability', style: TextStyle(color: CsColors.faint, fontSize: 11))),
        Expanded(child: Text('macOS', textAlign: TextAlign.center, style: TextStyle(color: CsColors.faint, fontSize: 11))),
        Expanded(child: Text('Mobile', textAlign: TextAlign.center, style: TextStyle(color: CsColors.faint, fontSize: 11))),
        Expanded(child: Text('MAS', textAlign: TextAlign.center, style: TextStyle(color: CsColors.faint, fontSize: 11))),
        Expanded(child: Text('Windows', textAlign: TextAlign.center, style: TextStyle(color: CsColors.faint, fontSize: 11))),
      ],
    );
  }
}

class _CoverageLine extends StatelessWidget {
  const _CoverageLine({required this.row});

  final _CoverageRow row;

  Widget _mark(bool value) => Icon(
        value ? Icons.check_circle_rounded : Icons.remove_circle_outline_rounded,
        size: 16,
        color: value ? CsColors.green : CsColors.faint,
      );

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        children: [
          Expanded(flex: 5, child: Text(row.label, style: const TextStyle(fontSize: 12, height: 1.3))),
          Expanded(child: Center(child: _mark(row.mac))),
          Expanded(child: Center(child: _mark(row.mobile))),
          Expanded(child: Center(child: _mark(row.mas))),
          Expanded(child: Center(child: _mark(row.windows))),
        ],
      ),
    );
  }
}

class _Bullet extends StatelessWidget {
  const _Bullet(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Padding(
            padding: EdgeInsets.only(top: 6),
            child: Icon(Icons.circle, size: 4, color: CsColors.primary),
          ),
          const SizedBox(width: 9),
          Expanded(
            child: Text(text, style: const TextStyle(color: CsColors.muted, fontSize: 12, height: 1.45)),
          ),
        ],
      ),
    );
  }
}
