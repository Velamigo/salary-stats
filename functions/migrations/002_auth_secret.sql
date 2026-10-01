-- 密码哈希存储 + 收紧 meta 表访问
CREATE TABLE IF NOT EXISTS auth_secret (
  k text PRIMARY KEY,
  salt text NOT NULL DEFAULT '',
  v text NOT NULL,          -- sha256(salt + ":" + secret)
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE auth_secret ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON auth_secret FROM anon, authenticated;
-- 无任何政策 = 外部读写全拒, 只有 Edge Function(内部 key 绕 RLS)能动
-- 行: pass_hash = 登录密码(加盐哈希), recovery_hash = 一次性恢复码(加盐哈希)
