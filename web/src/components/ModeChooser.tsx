import { Checkbox, Table, Tooltip } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';

import type { TLSMode } from '@/api/types';

interface Props {
  value: TLSMode;
  onChange: (v: TLSMode) => void;
  /** 直通不可用时的原因。给了就置灰直通卡片并显示这句话 —— 不隐藏。 */
  passthroughDisabledReason?: string | undefined;
}

const PASS_PROS = ['passthroughPro1', 'passthroughPro2'] as const;
const PASS_CONS = ['passthroughCon1', 'passthroughCon2', 'passthroughCon3', 'passthroughCon4'] as const;
const GW_PROS = ['gatewayPro1', 'gatewayPro2', 'gatewayPro3', 'gatewayPro4'] as const;
const GW_CONS = ['gatewayCon1'] as const;

/**
 * 模式选择：**两张并排单选卡，绝不是下拉框**。
 *
 * 下拉框会把一个改变信任边界的决定压缩成一个词。卡片各自写明得到什么、
 * 失去什么，用户因此学到代价 —— 这正是「诚实机制」的第一层。
 * 第二层是网关独有字段在直通下**置灰并给出原因**（见向导第 ② 步），
 * 第三层是实时页签里那句字面说明。
 */
export default function ModeChooser({
  value,
  onChange,
  passthroughDisabledReason,
}: Props): React.JSX.Element {
  const { t } = useTranslation(['tunnels', 'common']);
  const passDisabled = passthroughDisabledReason !== undefined;

  const card = (mode: TLSMode): React.JSX.Element => {
    const selected = value === mode;
    const disabled = mode === 'passthrough' && passDisabled;
    const pros = mode === 'passthrough' ? PASS_PROS : GW_PROS;
    const cons = mode === 'passthrough' ? PASS_CONS : GW_CONS;

    const body = (
      <div
        className={`flex-1 rounded-4px border p-14px ${
          selected ? 'border-primary' : 'border-line-2'
        } ${disabled ? 'opacity-50' : 'cursor-pointer'}`}
        style={selected ? { borderColor: 'rgb(var(--primary-6))' } : undefined}
        onClick={() => {
          if (!disabled) onChange(mode);
        }}
        role="radio"
        aria-checked={selected}
        aria-disabled={disabled}
        tabIndex={disabled ? -1 : 0}
        onKeyDown={(e) => {
          if (!disabled && (e.key === 'Enter' || e.key === ' ')) onChange(mode);
        }}
      >
        <div className="flex items-center gap-8px">
          <Checkbox checked={selected} disabled={disabled} onChange={() => onChange(mode)} />
          <span className="text-15px font-medium">
            {mode === 'passthrough' ? t('common:mode.passthroughFull') : t('common:mode.gatewayFull')}
          </span>
          {mode === 'gateway' ? (
            <span className="rounded-2px px-6px py-1px text-11px" style={{ background: 'var(--color-fill-2)' }}>
              {t('tunnels:wizard.mode.recommended')}
            </span>
          ) : null}
        </div>
        <div className="muted-note mt-6px">
          {mode === 'passthrough'
            ? t('tunnels:wizard.mode.passthroughTagline')
            : t('tunnels:wizard.mode.gatewayTagline')}
        </div>
        <ul className="mt-10px flex list-none flex-col gap-4px p-0 text-13px">
          {pros.map((k) => (
            <li key={k} className="flex gap-6px">
              <span style={{ color: 'rgb(var(--success-6))' }} aria-hidden="true">
                ✓
              </span>
              <span>{t(`tunnels:wizard.mode.${k}` as const)}</span>
            </li>
          ))}
          {cons.map((k) => (
            <li key={k} className="flex gap-6px">
              <span style={{ color: 'rgb(var(--danger-6))' }} aria-hidden="true">
                ✗
              </span>
              <span>{t(`tunnels:wizard.mode.${k}` as const)}</span>
            </li>
          ))}
          {mode === 'gateway' ? (
            <li className="flex gap-6px text-3">
              <span aria-hidden="true">·</span>
              <span>{t('tunnels:wizard.mode.gatewayCon2')}</span>
            </li>
          ) : null}
        </ul>
      </div>
    );

    return disabled ? <Tooltip content={passthroughDisabledReason}>{body}</Tooltip> : body;
  };

  type Row = { item: string; passthrough: string; gateway: string };
  const yes = '✓';
  const no = '✗';
  const rows: Row[] = [
    {
      item: t('tunnels:wizard.mode.compare.keyLocation'),
      passthrough: t('tunnels:wizard.mode.compare.keyLocationPassthrough'),
      gateway: t('tunnels:wizard.mode.compare.keyLocationGateway'),
    },
    { item: t('tunnels:wizard.mode.compare.plaintext'), passthrough: no, gateway: yes },
    { item: t('tunnels:wizard.mode.compare.acme'), passthrough: no, gateway: yes },
    {
      item: t('tunnels:wizard.mode.compare.hostRouting'),
      passthrough: t('tunnels:wizard.mode.compare.hostRoutingPassthrough'),
      gateway: yes,
    },
    { item: t('tunnels:wizard.mode.compare.injectAuth'), passthrough: no, gateway: yes },
    {
      item: t('tunnels:wizard.mode.compare.realIP'),
      passthrough: t('tunnels:wizard.mode.compare.realIPPassthrough'),
      gateway: t('tunnels:wizard.mode.compare.realIPGateway'),
    },
    { item: t('tunnels:wizard.mode.compare.httpMetrics'), passthrough: no, gateway: yes },
    {
      item: t('tunnels:wizard.mode.compare.esp32'),
      passthrough: yes,
      gateway: t('tunnels:wizard.mode.compare.esp32Gateway'),
    },
  ];

  return (
    <div className="flex flex-col gap-14px">
      <div className="text-15px font-medium">{t('tunnels:wizard.mode.question')}</div>
      <div className="flex flex-col gap-12px sm:flex-row">
        {card('passthrough')}
        {card('gateway')}
      </div>
      {passDisabled ? (
        <div className="text-13px" style={{ color: 'rgb(var(--warning-6))' }}>
          {passthroughDisabledReason}
        </div>
      ) : null}
      <Table
        size="mini"
        rowKey="item"
        pagination={false}
        data={rows}
        columns={[
          { title: t('tunnels:wizard.mode.compareItem'), dataIndex: 'item' },
          { title: t('common:mode.passthroughFull'), dataIndex: 'passthrough', width: 160 },
          { title: t('common:mode.gatewayFull'), dataIndex: 'gateway', width: 160 },
        ]}
      />
    </div>
  );
}
