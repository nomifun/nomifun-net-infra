/**
 * 客户端形状校验。**只管形状，不管语义**。
 *
 * 权威校验是一次往返（`POST /api/tunnels:validate`）：端口冲突、
 * passthrough+ACME、router=http 需要 gateway 这类规则是跨字段且服务端作用域的，
 * codegen 出不来，写在这里只会得到「编码了规则的弱一半却暗示编码了全部」。
 * 这里存在的唯一理由是**手感**：让用户在敲错 slug 的那一刻就看到红字，
 * 而不是等提交往返一圈。
 */

import { z } from 'zod';

/** 与 Go 侧 slugPattern 逐字一致（internal/tunnel/tunnel.go）。 */
export const slugSchema = z
  .string()
  .regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/, 'slug');

/** host:port。端口范围也查，因为 0 与 >65535 是最常见的手误。 */
export const hostPortSchema = z.string().refine((v) => {
  const i = v.lastIndexOf(':');
  if (i <= 0) return false;
  const port = Number(v.slice(i + 1));
  return Number.isInteger(port) && port > 0 && port <= 65_535;
}, 'addr');

export const cidrSchema = z.string().refine((v) => {
  const [addr, len, ...rest] = v.split('/');
  if (rest.length > 0 || addr === undefined || len === undefined) return false;
  const bits = Number(len);
  if (!Number.isInteger(bits) || bits < 0) return false;
  // IPv6 到 128 位，IPv4 到 32 位；只做粗判，权威判断在 Go 的 netip.ParsePrefix。
  return addr.includes(':') ? bits <= 128 : bits <= 32 && addr.split('.').length === 4;
}, 'cidr');

export const draftShape = z.object({
  slug: slugSchema,
  addr: hostPortSchema,
});

/** 返回出错的字段名集合，供表单高亮。 */
export function shapeErrors(slug: string, addr: string): Set<'slug' | 'addr'> {
  const bad = new Set<'slug' | 'addr'>();
  if (!slugSchema.safeParse(slug).success) bad.add('slug');
  if (!hostPortSchema.safeParse(addr).success) bad.add('addr');
  return bad;
}
