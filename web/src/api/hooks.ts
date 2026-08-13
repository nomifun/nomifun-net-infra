/**
 * swr 读钩子 + 一个 apiMutate 助手。
 *
 * swr 的真实弱点是 mutation，答案是这个助手而不是再引入第二套缓存模型
 * （dossier 11「swr over TanStack Query」）。
 */

import { useCallback, useMemo, useSyncExternalStore } from 'react';
import useSWR, { mutate, type SWRResponse } from 'swr';

import { ApiError, api, type Identity, type SetupState } from './client';
import { keys } from './keys';
import { stream, type StreamHealth } from './stream';
import type {
  AgentStatus,
  LearnedSources,
  RelayEvent,
  Sample,
  SettingsGroup,
  Snapshot,
  TurnAllocation,
  Tunnel,
} from './types';

/** 全局 swr 配置。SSE 负责「活」，所以关掉一切轮询。 */
export const swrConfig = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  shouldRetryOnError: (err: unknown) =>
    !(err instanceof ApiError && (err.isUnauthenticated || err.status === 404)),
  errorRetryCount: 3,
} as const;

export function useSetupState(): SWRResponse<SetupState, ApiError> {
  return useSWR<SetupState, ApiError>(keys.setupState, api.setupState);
}

/** 当前身份。401 时 data 为 undefined、error.isUnauthenticated 为真。 */
export function useIdentity(): SWRResponse<Identity, ApiError> {
  return useSWR<Identity, ApiError>(keys.me, api.me);
}

export function useSnapshot(): SWRResponse<Snapshot, ApiError> {
  return useSWR<Snapshot, ApiError>(keys.snapshot, api.snapshot);
}

export function useTunnels(): SWRResponse<Tunnel[], ApiError> {
  return useSWR<Tunnel[], ApiError>(keys.tunnels, async () => (await api.listTunnels()) ?? []);
}

/**
 * 按 slug 取隧道。
 *
 * 后端路由用 ID，但**URL 里必须是人类可读的 slug**（spec §8.1）。
 * 这里从列表里解析，而不是加一个 by-slug 端点：列表本来就已经在缓存里，
 * 多一次请求换不来任何东西。
 */
export function useTunnelBySlug(slug: string | undefined): {
  tunnel: Tunnel | undefined;
  error: ApiError | undefined;
  isLoading: boolean;
} {
  const { data, error, isLoading } = useTunnels();
  const tunnel = useMemo(() => (data ?? []).find((t) => t.slug === slug), [data, slug]);
  return {
    tunnel,
    error: error ?? undefined,
    isLoading,
  };
}

export function useAgents(): SWRResponse<AgentStatus[], ApiError> {
  return useSWR<AgentStatus[], ApiError>(keys.agents, async () => (await api.listAgents()) ?? []);
}

export function useRecentEvents(limit = 100): SWRResponse<{ events: RelayEvent[] }, ApiError> {
  return useSWR<{ events: RelayEvent[] }, ApiError>(keys.recentEvents, async () => ({
    events: (await api.recentEvents(limit)) ?? [],
  }));
}

export function useSettings(): SWRResponse<SettingsGroup[], ApiError> {
  return useSWR<SettingsGroup[], ApiError>(
    keys.settings,
    async () => (await api.settings()).groups ?? [],
  );
}

export function useTurnAllocations(): SWRResponse<TurnAllocation[], ApiError> {
  return useSWR<TurnAllocation[], ApiError>(
    keys.turn,
    async () => (await api.turnAllocations()).allocations ?? [],
  );
}

export interface SamplesResult {
  samples: Sample[];
  rtt: { p50_us: number; p95_us: number; p99_us: number };
}

export function useSamples(
  id: string | undefined,
  fromSec: number,
): SWRResponse<SamplesResult, ApiError> {
  return useSWR<SamplesResult, ApiError>(id ? keys.samples(id, fromSec) : null, () =>
    api.samples(id ?? '', fromSec),
  );
}

/**
 * 学习模式观测到的来源。
 *
 * 刷新间隔给得比别处长（30s）：这份数据的更新频率由外部连接决定，
 * 而一份地址列表不需要秒级新鲜 —— 而它下面挂着勾选框，
 * 每秒重排一次会让人勾不中。
 */
export function useLearnedSources(
  id: string | undefined,
): SWRResponse<LearnedSources, ApiError> {
  return useSWR<LearnedSources, ApiError>(id ? keys.learned(id) : null, () =>
    api.learnedSources(id ?? ''),
    { refreshInterval: 30_000 },
  );
}

/** 订阅 SSE 流健康。组件挂载即开流，全部卸载才断流（引用计数在 stream.ts）。 */
export function useStreamHealth(): StreamHealth {
  return useSyncExternalStore(stream.subscribe, stream.getHealth, stream.getHealth);
}

/**
 * 写操作助手：跑 mutation，成功后失效相关 key。
 *
 * 不做乐观回滚：中继是权威，隧道的 state 由它决定，
 * 本地先猜一个 active 再被打回去只会让界面闪。
 */
export function useApiMutate(): <T>(
  fn: () => Promise<T>,
  invalidate?: readonly string[],
) => Promise<T> {
  return useCallback(async <T>(fn: () => Promise<T>, invalidate: readonly string[] = []) => {
    const out = await fn();
    await Promise.all(invalidate.map((k) => mutate(k)));
    return out;
  }, []);
}
