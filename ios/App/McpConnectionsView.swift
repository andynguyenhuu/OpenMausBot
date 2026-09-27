import CompanionCore
import SwiftUI
import UIKit

/// Status and reconnect for remote MCP servers' OAuth handshakes.
///
/// Adding a brand-new `mcpServers` entry stays desktop-only (see the
/// companion allowlist comment in companion/src/routes.ts) — this screen only
/// shows connections that already exist, and lets a pending, expired, or
/// errored one be (re)started without needing the desktop UI open.
struct McpConnectionsView: View {
    @EnvironmentObject private var session: Session
    @Environment(\.scenePhase) private var scenePhase
    @State private var connections: [McpOAuthConnectionSummary]?
    @State private var loading = true
    @State private var refreshing = false
    @State private var connectingId: String?

    var body: some View {
        List {
            if let connections, connections.isEmpty {
                Section {
                    EmptyStateView(
                        "No MCP connections yet",
                        systemImage: "link.circle",
                        description: Text("Add a remote MCP server on your computer first. Once it needs sign-in, it shows up here to finish from your phone.")
                    )
                }
            } else if let connections {
                Section {
                    ForEach(connections) { connection in
                        connectionRow(connection)
                    }
                } footer: {
                    Text("Signing in opens the provider's page in Safari. Come back here afterwards — status updates on its own.")
                }
            }
        }
        .navigationTitle("MCP Connections")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Refresh", systemImage: "arrow.clockwise") {
                    Task { await refresh(showProgress: true) }
                }
                .disabled(refreshing)
            }
        }
        .overlay { if loading { ProgressView() } }
        .task { await load() }
        .refreshable { await refresh() }
        .onValueChange(of: scenePhase) { phase in
            if phase == .active { Task { await refresh() } }
        }
    }

    @ViewBuilder
    private func connectionRow(_ connection: McpOAuthConnectionSummary) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(connection.serverName ?? connection.serverUrl)
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                if connection.serverName != nil {
                    Text(connection.serverUrl)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
                statusLabel(for: connection)
                    .font(.caption)
            }
            Spacer()
            if connectingId == connection.connectionId {
                ProgressView().controlSize(.small)
            } else if connection.needsReconnect {
                Button(connection.status == "pending" ? "Connect" : "Reconnect") {
                    Task { await connect(connection) }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        }
    }

    @ViewBuilder
    private func statusLabel(for connection: McpOAuthConnectionSummary) -> some View {
        switch connection.status {
        case "connected":
            Label("Connected", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case "pending":
            Label("Needs sign-in", systemImage: "clock").foregroundStyle(.secondary)
        case "expired":
            Label("Expired — reconnect", systemImage: "exclamationmark.circle").foregroundStyle(.orange)
        default:
            Label(connection.error ?? "Connection error", systemImage: "xmark.circle")
                .foregroundStyle(.red)
                .lineLimit(2)
        }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        connections = await session.loadMcpOAuthConnections()
    }

    private func refresh(showProgress: Bool = false) async {
        if showProgress { refreshing = true }
        defer { if showProgress { refreshing = false } }
        if let updated = await session.loadMcpOAuthConnections() {
            connections = updated
        }
    }

    private func connect(_ connection: McpOAuthConnectionSummary) async {
        connectingId = connection.connectionId
        defer { connectingId = nil }
        guard let url = await session.startMcpOAuthConnection(
            serverUrl: connection.serverUrl,
            serverName: connection.serverName,
            connectionId: connection.connectionId
        ) else { return }
        guard await UIApplication.shared.open(url) else {
            session.actionError = "The sign-in page could not be opened. Try again after checking your browser restrictions."
            return
        }
    }
}
