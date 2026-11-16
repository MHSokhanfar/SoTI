import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  BellRing,
  CheckCheck,
  Mail,
  Settings2,
  ShieldAlert,
  SlidersHorizontal,
  Trash2,
  X,
} from 'lucide-react';
import type { QuotaState } from '../App';
import type {
  AlertRuleTriggerHistoryEntry,
  CustomAlertRule,
  DesktopRuleNotification,
} from '../utils/alertRules';
import type { EmailAlertRecord } from '../utils/emailAlerts';
import {
  countUnreadNotifications,
  detectQuotaThresholdCrossings,
  dismissNotificationAlert,
  formatAlertTimestamp,
  markAllNotificationsRead,
  markNotificationRead,
  mergeNotificationAlerts,
  QUOTA_ALERT_THRESHOLD_PERCENT,
  type QuotaNotificationAlert,
} from '../utils/notifications';
import { maskIndicatorValue, maskSensitiveText } from '../utils/privacyMode';
import type { LookupResult } from '../utils/indicators';
import { AlertRulesPanel } from './AlertRulesPanel';
import { EmailAlertSettingsPanel } from './EmailAlertSettingsPanel';
import { usePrivacyMode } from './PrivacyModeContext';

export type NotificationCenterTab = 'alerts' | 'alert_rules' | 'email_rules';

interface NotificationCenterProps {
  quotaState: QuotaState;
  emailAlerts?: EmailAlertRecord[];
  emailAlertsRefreshNonce?: number;
  alertRules?: CustomAlertRule[];
  confidenceThreshold?: number;
  onChangeConfidenceThreshold?: (next: number) => void;
  desktopRuleAlerts?: DesktopRuleNotification[];
  activeDesktopToastIds?: string[];
  alertRuleHistory?: AlertRuleTriggerHistoryEntry[];
  currentResults?: readonly LookupResult[];
  isOpen: boolean;
  requestedTab?: NotificationCenterTab | null;
  onOpenPanel: () => void;
  onClosePanel: () => void;
  onUnreadCountChange: (count: number) => void;
  onNavigateToApis: () => void;
  onEmailAlertDispatched?: (record: EmailAlertRecord) => void;
  onClearEmailAlerts?: () => void;
  onSaveAlertRule?: (rule: CustomAlertRule) => void;
  onToggleAlertRule?: (ruleId: string) => void;
  onDeleteAlertRule?: (ruleId: string) => void;
  onTestAlertRule?: (rule: CustomAlertRule) => Promise<{ ok: boolean; message: string }>;
  onEvaluateAlertRulesNow?: () => { matchedRules: number; message: string };
  onClearAlertRuleHistory?: () => void;
  onMarkDesktopAlertRead?: (id: string) => void;
  onDismissDesktopAlert?: (id: string) => void;
  onMarkAllDesktopAlertsRead?: () => void;
  onClearDesktopAlerts?: () => void;
  onDismissDesktopToast?: (id: string) => void;
}

export function NotificationCenter({
  quotaState,
  emailAlerts = [],
  emailAlertsRefreshNonce = 0,
  alertRules = [],
  confidenceThreshold = 0,
  onChangeConfidenceThreshold,
  desktopRuleAlerts = [],
  activeDesktopToastIds = [],
  alertRuleHistory = [],
  currentResults = [],
  isOpen,
  requestedTab = null,
  onOpenPanel,
  onClosePanel,
  onUnreadCountChange,
  onNavigateToApis,
  onEmailAlertDispatched,
  onClearEmailAlerts,
  onSaveAlertRule,
  onToggleAlertRule,
  onDeleteAlertRule,
  onTestAlertRule,
  onEvaluateAlertRulesNow,
  onClearAlertRuleHistory,
  onMarkDesktopAlertRead,
  onDismissDesktopAlert,
  onMarkAllDesktopAlertsRead,
  onClearDesktopAlerts,
  onDismissDesktopToast,
}: NotificationCenterProps) {
  const privacyMode = usePrivacyMode();
  const [activeTab, setActiveTab] = useState<NotificationCenterTab>('alerts');
  const [alerts, setAlerts] = useState<QuotaNotificationAlert[]>([]);
  const [readEmailIds, setReadEmailIds] = useState<string[]>([]);
  const [dismissedEmailIds, setDismissedEmailIds] = useState<string[]>([]);
  const [activeToastIds, setActiveToastIds] = useState<string[]>([]);
  const previousPercentByKeyRef = useRef<Record<string, number>>({});
  const toastTimersRef = useRef<Map<string, number>>(new Map());
  const panelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (requestedTab) {
      setActiveTab(requestedTab);
    }
  }, [requestedTab]);

  // Listen continuously to App's quotaState regardless of which view is active
  useEffect(() => {
    const { alertsToPush, nextPercentByKey } = detectQuotaThresholdCrossings(
      quotaState,
      previousPercentByKeyRef.current,
      QUOTA_ALERT_THRESHOLD_PERCENT,
    );
    previousPercentByKeyRef.current = nextPercentByKey;

    if (alertsToPush.length === 0) return;

    setAlerts((prev) => mergeNotificationAlerts(prev, alertsToPush));
    setActiveToastIds((prev) => [
      ...alertsToPush.map((a) => a.id),
      ...prev.filter((id) => !alertsToPush.some((a) => a.id === id)),
    ].slice(0, 3));

    for (const alert of alertsToPush) {
      const existingTimer = toastTimersRef.current.get(alert.id);
      if (existingTimer !== undefined) {
        window.clearTimeout(existingTimer);
      }
      const timer = window.setTimeout(() => {
        setActiveToastIds((prev) => prev.filter((id) => id !== alert.id));
        toastTimersRef.current.delete(alert.id);
      }, 10000);
      toastTimersRef.current.set(alert.id, timer);
    }
  }, [quotaState]);

  const visibleEmailAlerts = useMemo(
    () => emailAlerts.filter((item) => !dismissedEmailIds.includes(item.id)),
    [emailAlerts, dismissedEmailIds],
  );

  const unreadEmailCount = useMemo(
    () => visibleEmailAlerts.filter((item) => !readEmailIds.includes(item.id)).length,
    [visibleEmailAlerts, readEmailIds],
  );

  const unreadDesktopCount = useMemo(
    () => desktopRuleAlerts.filter((item) => !item.read).length,
    [desktopRuleAlerts],
  );

  const unreadCount = useMemo(
    () => countUnreadNotifications(alerts) + unreadEmailCount + unreadDesktopCount,
    [alerts, unreadEmailCount, unreadDesktopCount],
  );

  useEffect(() => {
    onUnreadCountChange(unreadCount);
  }, [unreadCount, onUnreadCountChange]);

  useEffect(() => {
    return () => {
      for (const timer of toastTimersRef.current.values()) {
        window.clearTimeout(timer);
      }
      toastTimersRef.current.clear();
    };
  }, []);

  useEffect(() => {
    if (!isOpen) return;

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClosePanel();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClosePanel]);

  const activeQuotaToasts = useMemo(
    () => alerts.filter((a) => activeToastIds.includes(a.id)),
    [alerts, activeToastIds],
  );

  const activeDesktopToasts = useMemo(
    () => desktopRuleAlerts.filter((d) => activeDesktopToastIds.includes(d.id)),
    [desktopRuleAlerts, activeDesktopToastIds],
  );

  function dismissToastPopup(id: string) {
    const timer = toastTimersRef.current.get(id);
    if (timer !== undefined) {
      window.clearTimeout(timer);
      toastTimersRef.current.delete(id);
    }
    setActiveToastIds((prev) => prev.filter((item) => item !== id));
  }

  function handleDismissAlert(id: string) {
    dismissToastPopup(id);
    setAlerts((prev) => dismissNotificationAlert(prev, id));
  }

  function handleMarkAllRead() {
    setAlerts((prev) => markAllNotificationsRead(prev));
    setReadEmailIds((prev) => {
      const next = new Set(prev);
      for (const item of visibleEmailAlerts) next.add(item.id);
      return Array.from(next);
    });
    onMarkAllDesktopAlertsRead?.();
  }

  function handleClearAll() {
    for (const timer of toastTimersRef.current.values()) {
      window.clearTimeout(timer);
    }
    toastTimersRef.current.clear();
    setActiveToastIds([]);
    setAlerts([]);
    setDismissedEmailIds(emailAlerts.map((item) => item.id));
    onClearEmailAlerts?.();
    onClearDesktopAlerts?.();
  }

  const totalAlertsCount = alerts.length + visibleEmailAlerts.length + desktopRuleAlerts.length;

  return (
    <>
      {isOpen && (
        <>
          <div
            aria-hidden="true"
            onClick={onClosePanel}
            className="fixed inset-0 z-20 bg-slate-950/15 dark:bg-black/35 backdrop-blur-[1px]"
          />

          <div
            ref={panelRef}
            role="dialog"
            aria-modal="false"
            aria-label="Notification Center and Alert Rules"
            data-testid="notification-center-panel"
            className="fixed right-3 top-[70px] left-3 z-50 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl sm:left-auto sm:right-6 sm:w-[540px]"
          >
            <div className="flex items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 px-4 py-3">
              <div className="flex items-center gap-2 min-w-0">
                <Bell className="h-4 w-4 text-slate-700 dark:text-slate-300 shrink-0" aria-hidden="true" />
                <h2 className="text-sm font-semibold text-slate-950 dark:text-slate-50 whitespace-nowrap shrink-0">
                  Notification Center
                </h2>
                <span className="font-mono text-[11px] font-medium text-slate-500 dark:text-slate-400 tabular-nums whitespace-nowrap shrink-0">
                  · {unreadCount} unread
                </span>
              </div>

              <div className="flex items-center gap-1.5 shrink-0">
                {activeTab === 'alerts' && unreadCount > 0 && (
                  <button
                    type="button"
                    onClick={handleMarkAllRead}
                    className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                  >
                    <CheckCheck className="h-3.5 w-3.5" aria-hidden="true" />
                    Mark read
                  </button>
                )}
                {activeTab === 'alerts' && totalAlertsCount > 0 && (
                  <button
                    type="button"
                    onClick={handleClearAll}
                    aria-label="Clear all notifications"
                    className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                    Clear
                  </button>
                )}
                <button
                  type="button"
                  onClick={onClosePanel}
                  aria-label="Close notification center"
                  className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>
            </div>

            <div className="border-b border-slate-100 dark:border-slate-800 px-4 py-2 overflow-x-auto">
              <div
                className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1"
                role="tablist"
                aria-label="Notification Center sections"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'alerts'}
                  data-testid="notification-tab-alerts"
                  onClick={() => setActiveTab('alerts')}
                  className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    activeTab === 'alerts'
                      ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                  }`}
                >
                  <Bell className="h-3.5 w-3.5" aria-hidden="true" />
                  Alerts ({totalAlertsCount})
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'alert_rules'}
                  data-testid="notification-tab-alert-rules"
                  onClick={() => setActiveTab('alert_rules')}
                  className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    activeTab === 'alert_rules'
                      ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                  }`}
                >
                  <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
                  Alert Rules ({alertRules.filter((r) => r.enabled).length})
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'email_rules'}
                  data-testid="notification-tab-email-rules"
                  onClick={() => setActiveTab('email_rules')}
                  className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    activeTab === 'email_rules'
                      ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                  }`}
                >
                  <Mail className="h-3.5 w-3.5" aria-hidden="true" />
                  Email Rules
                </button>
              </div>
            </div>

            <div className="max-h-[68vh] overflow-y-auto">
              {activeTab === 'alert_rules' ? (
                <AlertRulesPanel
                  compact
                  rules={alertRules}
                  confidenceThreshold={confidenceThreshold}
                  onChangeConfidenceThreshold={onChangeConfidenceThreshold}
                  history={alertRuleHistory}
                  currentResults={currentResults}
                  onSaveRule={(rule) => onSaveAlertRule?.(rule)}
                  onToggleRule={(id) => onToggleAlertRule?.(id)}
                  onDeleteRule={(id) => onDeleteAlertRule?.(id)}
                  onTestRule={
                    onTestAlertRule ||
                    (async () => ({ ok: false, message: 'Rule testing unavailable.' }))
                  }
                  onEvaluateCurrentResults={onEvaluateAlertRulesNow}
                  onClearHistory={onClearAlertRuleHistory}
                />
              ) : activeTab === 'email_rules' ? (
                <EmailAlertSettingsPanel
                  compact
                  refreshNonce={emailAlertsRefreshNonce}
                  onAlertDispatched={onEmailAlertDispatched}
                />
              ) : totalAlertsCount === 0 ? (
                <div className="px-5 py-8 text-center">
                  <Bell className="mx-auto h-6 w-6 text-slate-400 dark:text-slate-500" aria-hidden="true" />
                  <p className="mt-2 text-sm font-medium text-slate-900 dark:text-slate-100">
                    No active threshold or quota alerts
                  </p>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    Quota alerts trigger above {QUOTA_ALERT_THRESHOLD_PERCENT}% usage, and custom Alert Rules trigger desktop or email alerts automatically on investigation results.
                  </p>
                  <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
                    <button
                      type="button"
                      onClick={() => setActiveTab('alert_rules')}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-3 py-1.5 text-xs font-medium text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 cursor-pointer"
                    >
                      <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
                      Configure Alert Rules
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab('email_rules')}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
                    >
                      <Mail className="h-3.5 w-3.5" aria-hidden="true" />
                      Email Rules
                    </button>
                  </div>
                </div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-800">
                  {desktopRuleAlerts.map((item) => (
                    <div
                      key={item.id}
                      data-testid={`desktop-rule-notification-item-${item.id}`}
                      className={`px-4 py-3.5 transition-colors ${
                        item.read
                          ? 'bg-white dark:bg-slate-900'
                          : 'bg-amber-50/45 dark:bg-amber-950/15'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <BellRing
                          className="mt-0.5 h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0"
                          aria-hidden="true"
                        />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="text-[11px] font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-400">
                                Alert Rule Triggered
                              </span>
                              <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                              <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                                {formatAlertTimestamp(item.createdAt)}
                              </span>
                            </div>
                            {!item.read && (
                              <span
                                title="Unread alert"
                                className="h-2 w-2 rounded-full bg-red-600 dark:bg-red-500 shrink-0"
                              />
                            )}
                          </div>

                          <p className="mt-1 text-xs font-semibold text-slate-950 dark:text-slate-50">
                            {item.ruleName} ({item.indicatorType.toUpperCase()} ≥ {item.minRiskScore}/100)
                          </p>
                          <p className="mt-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                            {item.matches
                              .slice(0, 3)
                              .map(
                                (m) =>
                                  `${maskIndicatorValue(m.indicator, m.type, privacyMode)} (${m.confidenceScore}/100 · ${m.riskLevel})`,
                              )
                              .join(', ')}
                          </p>

                          <div className="mt-2 flex flex-wrap items-center gap-3">
                            <button
                              type="button"
                              onClick={() => {
                                onMarkDesktopAlertRead?.(item.id);
                                setActiveTab('alert_rules');
                              }}
                              className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-700 dark:text-red-400 hover:underline cursor-pointer"
                            >
                              <Settings2 className="h-3 w-3" aria-hidden="true" />
                              Manage Alert Rules
                            </button>
                            {!item.read && (
                              <button
                                type="button"
                                onClick={() => onMarkDesktopAlertRead?.(item.id)}
                                className="text-[11px] font-medium text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100 cursor-pointer"
                              >
                                Mark read
                              </button>
                            )}
                          </div>
                        </div>

                        <button
                          type="button"
                          onClick={() => onDismissDesktopAlert?.(item.id)}
                          aria-label={`Dismiss rule alert ${item.ruleName}`}
                          className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 shrink-0 cursor-pointer"
                        >
                          <X className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </div>
                  ))}

                  {visibleEmailAlerts.map((item) => {
                    const isRead = readEmailIds.includes(item.id);
                    return (
                      <div
                        key={item.id}
                        data-testid={`email-notification-item-${item.id}`}
                        className={`px-4 py-3.5 transition-colors ${
                          isRead
                            ? 'bg-white dark:bg-slate-900'
                            : 'bg-red-50/40 dark:bg-red-950/15'
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <Mail
                            className="mt-0.5 h-4 w-4 text-red-600 dark:text-red-400 shrink-0"
                            aria-hidden="true"
                          />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center justify-between gap-2">
                              <div className="flex items-center gap-2 min-w-0">
                                <span className="text-[11px] font-semibold uppercase tracking-wide text-red-700 dark:text-red-400">
                                  IOC Email Alert
                                </span>
                                <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                                <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                                  {formatAlertTimestamp(item.createdAt)}
                                </span>
                              </div>
                              {!isRead && (
                                <span
                                  title="Unread alert"
                                  className="h-2 w-2 rounded-full bg-red-600 dark:bg-red-500 shrink-0"
                                />
                              )}
                            </div>

                            <p className="mt-1 text-xs font-semibold text-slate-950 dark:text-slate-50">
                              {maskSensitiveText(item.subject, privacyMode)}
                            </p>
                            <p className="mt-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                              To: {item.recipients.join(', ')} ·{' '}
                              {item.triggeredIndicators
                                .slice(0, 3)
                                .map(
                                  (t) =>
                                    `${maskIndicatorValue(t.indicator, null, privacyMode)} (${t.confidenceScore}/100)`,
                                )
                                .join(', ')}
                            </p>
                            <div className="mt-2 flex flex-wrap items-center gap-3">
                              <button
                                type="button"
                                onClick={() => {
                                  setReadEmailIds((prev) =>
                                    prev.includes(item.id) ? prev : [...prev, item.id],
                                  );
                                  setActiveTab('email_rules');
                                }}
                                className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-700 dark:text-red-400 hover:underline cursor-pointer"
                              >
                                <Settings2 className="h-3 w-3" aria-hidden="true" />
                                View Outbox &amp; Rules
                              </button>
                              {!isRead && (
                                <button
                                  type="button"
                                  onClick={() =>
                                    setReadEmailIds((prev) =>
                                      prev.includes(item.id) ? prev : [...prev, item.id],
                                    )
                                  }
                                  className="text-[11px] font-medium text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100 cursor-pointer"
                                >
                                  Mark read
                                </button>
                              )}
                            </div>
                          </div>

                          <button
                            type="button"
                            onClick={() => setDismissedEmailIds((prev) => [...prev, item.id])}
                            aria-label="Dismiss threshold email alert"
                            className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 shrink-0 cursor-pointer"
                          >
                            <X className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        </div>
                      </div>
                    );
                  })}

                  {alerts.map((alert) => {
                    const isCritical = alert.severity === 'critical';
                    return (
                      <div
                        key={alert.id}
                        data-testid={`notification-item-${alert.providerId}`}
                        className={`px-4 py-3.5 transition-colors ${
                          alert.read
                            ? 'bg-white dark:bg-slate-900'
                            : 'bg-amber-50/40 dark:bg-amber-950/15'
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className="mt-0.5 shrink-0">
                            {isCritical ? (
                              <ShieldAlert className="h-4 w-4 text-red-600 dark:text-red-400" aria-hidden="true" />
                            ) : (
                              <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400" aria-hidden="true" />
                            )}
                          </div>

                          <div className="min-w-0 flex-1">
                            <div className="flex items-center justify-between gap-2">
                              <div className="flex items-center gap-2 min-w-0">
                                <span
                                  className={`text-[11px] font-semibold uppercase tracking-wide ${
                                    isCritical
                                      ? 'text-red-700 dark:text-red-400'
                                      : 'text-amber-700 dark:text-amber-400'
                                  }`}
                                >
                                  {isCritical ? 'Quota Reached' : '90%+ Warning'}
                                </span>
                                <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                                <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                                  {formatAlertTimestamp(alert.createdAt)}
                                </span>
                              </div>
                              {!alert.read && (
                                <span
                                  title="Unread alert"
                                  className="h-2 w-2 rounded-full bg-red-600 dark:bg-red-500 shrink-0"
                                />
                              )}
                            </div>

                            <p className="mt-1 text-xs font-semibold text-slate-950 dark:text-slate-50">
                              {alert.title}
                            </p>
                            <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-300">
                              {alert.message}
                            </p>

                            <div className="mt-2 flex flex-wrap items-center gap-3">
                              <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                                Usage: {alert.used}/{alert.limit} ({alert.percentUsed}%)
                              </span>
                              <button
                                type="button"
                                onClick={() => {
                                  setAlerts((prev) => markNotificationRead(prev, alert.id));
                                  onNavigateToApis();
                                }}
                                className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-700 dark:text-red-400 hover:underline cursor-pointer"
                              >
                                <Settings2 className="h-3 w-3" aria-hidden="true" />
                                Manage APIs
                              </button>
                              {!alert.read && (
                                <button
                                  type="button"
                                  onClick={() => setAlerts((prev) => markNotificationRead(prev, alert.id))}
                                  className="text-[11px] font-medium text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100 cursor-pointer"
                                >
                                  Mark read
                                </button>
                              )}
                            </div>
                          </div>

                          <button
                            type="button"
                            onClick={() => handleDismissAlert(alert.id)}
                            aria-label={`Dismiss ${alert.providerName} quota alert`}
                            className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 shrink-0 cursor-pointer"
                          >
                            <X className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {(activeDesktopToasts.length > 0 || (!isOpen && activeQuotaToasts.length > 0)) && (
        <div
          data-testid="quota-notification-toasts"
          aria-live="assertive"
          className={`fixed left-4 right-4 flex flex-col gap-2 sm:left-auto sm:right-6 sm:w-96 print:hidden ${
            isOpen
              ? 'bottom-4 z-[60]'
              : 'bottom-4 z-40 sm:bottom-auto sm:top-[72px]'
          }`}
        >
          {activeDesktopToasts.map((item) => {
            const top = item.matches[0];
            return (
              <div
                key={item.id}
                role="alert"
                data-testid="desktop-alert-rule-toast"
                className="flex items-start gap-3 rounded-xl border border-amber-300 dark:border-amber-800/80 bg-white dark:bg-slate-900 px-4 py-3 shadow-lg"
              >
                <BellRing className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-semibold text-slate-950 dark:text-slate-50">
                    Alert Rule: {item.ruleName}
                  </p>
                  <p className="mt-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                    {top
                      ? `${maskIndicatorValue(top.indicator, top.type, privacyMode)} (${top.confidenceScore}/100 · ${top.riskLevel})`
                      : `${item.matches.length} matched IOCs`}
                    {item.matches.length > 1 ? ` +${item.matches.length - 1} more` : ''}
                  </p>
                  <div className="mt-2 flex items-center gap-3">
                    <button
                      type="button"
                      onClick={() => {
                        onMarkDesktopAlertRead?.(item.id);
                        onDismissDesktopToast?.(item.id);
                        setActiveTab('alerts');
                        onOpenPanel();
                      }}
                      className="text-[11px] font-semibold text-slate-800 dark:text-slate-200 hover:underline cursor-pointer"
                    >
                      Inspect Alert
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        onDismissDesktopToast?.(item.id);
                        setActiveTab('alert_rules');
                        onOpenPanel();
                      }}
                      className="text-[11px] font-semibold text-red-700 dark:text-red-400 hover:underline cursor-pointer"
                    >
                      Edit Rule
                    </button>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onDismissDesktopToast?.(item.id)}
                  aria-label={`Dismiss rule alert ${item.ruleName}`}
                  className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 shrink-0 cursor-pointer"
                >
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            );
          })}

          {!isOpen && activeQuotaToasts.map((alert) => {
            const isCritical = alert.severity === 'critical';
            return (
              <div
                key={alert.id}
                role="alert"
                data-testid={`quota-alert-toast-${alert.providerId}`}
                className={`flex items-start gap-3 rounded-xl border bg-white dark:bg-slate-900 px-4 py-3 shadow-lg ${
                  isCritical
                    ? 'border-red-300 dark:border-red-800/80'
                    : 'border-amber-300 dark:border-amber-800/80'
                }`}
              >
                {isCritical ? (
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-red-600 dark:text-red-400" aria-hidden="true" />
                ) : (
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden="true" />
                )}

                <div className="min-w-0 flex-1">
                  <p className="text-xs font-semibold text-slate-950 dark:text-slate-50">
                    {alert.title}
                  </p>
                  <p className="mt-0.5 text-[11px] text-slate-600 dark:text-slate-300">
                    {alert.message}
                  </p>
                  <div className="mt-2 flex items-center gap-3">
                    <button
                      type="button"
                      onClick={() => {
                        setAlerts((prev) => markNotificationRead(prev, alert.id));
                        dismissToastPopup(alert.id);
                        onOpenPanel();
                      }}
                      className="text-[11px] font-semibold text-slate-800 dark:text-slate-200 hover:underline cursor-pointer"
                    >
                      Open Notification Center
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setAlerts((prev) => markNotificationRead(prev, alert.id));
                        dismissToastPopup(alert.id);
                        onNavigateToApis();
                      }}
                      className="text-[11px] font-semibold text-red-700 dark:text-red-400 hover:underline cursor-pointer"
                    >
                      Manage APIs
                    </button>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => dismissToastPopup(alert.id)}
                  aria-label={`Dismiss ${alert.providerName} quota alert banner`}
                  className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 shrink-0 cursor-pointer"
                >
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}
