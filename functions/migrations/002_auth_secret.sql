-- 密码哈希存储 + 收紧 meta 表访问
CREATE TABLE IF NOT EXISTS auth_secret (
  k text PRIMARY KEY,
  v text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE auth_secret ENABLE ROW LEVEL SECURITY;
-- 无任何政策 = anon/authenticated 读写全拒, 只有函数(内部 key 可绕 RLS)能动
