# isbench Makefile —— 静态构建规则
# build.sh 负责参数解析/工具链检查/组形态过滤, 生成 .vars.mk
# 本文件负责编译/核查/组装/打包的全部规则
#
# 命名契约(全链统一用 - 分隔组与形态):
#   目标名 = dist 产物名 = <grp>-<form> (如 scalar-x64_linux)
#   .vars.mk 提供: TARGETS, FORM_xxx, GRP_xxx, DIST_xxx

# ==== 包含 build.sh 生成的变量文件 ====
-include .vars.mk

# ==== 默认值 ====
TARGETS     ?=
HEADERS     := src/ib_core.h src/ib_buf.h src/ib_fields.h src/ib_gen.h
CFLAGS      := -O2 -static -msse2 -mno-avx -mno-avx2 -mno-fma
# LDLIBS: cfloat 组引入 sinl/expl/logl/sqrtl/acosl 等 libm 调用 -> 最终链接需 -lm。
# -lpthread: mingw-w64(msvcrt) 不提供 clock_gettime, 由 winpthreads 提供 shim
#   (cfloat 探针 cf_now 用 CLOCK_MONOTONIC); -static 下烘进 exe, 不引入运行期 DLL。
#   glibc(含 loongarch) 已把 pthread 并入 libc, -lpthread 为空桦, 无副作用。
# 对象在库前 -> 追加在链接命令末尾。
LDLIBS      := -lm -lpthread
# loongarch64 形态专用 flags: 去掉 x86 专有的 -msse2/-mno-avx*(交叉编译器不认),
# 只留 -O2 -static(cfloat 组的 loongarch64 原生基线二进制用)。
LOONGFLAGS  := -O2 -static

# ==== 工具链(按形态区分) ====
CC_x64_linux      := gcc
AR_x64_linux      := ar
CC_i386_linux         := gcc
AR_i386_linux         := ar
CC_x64_windows     := x86_64-w64-mingw32-gcc
AR_x64_windows     := x86_64-w64-mingw32-ar
CC_i386_windows       := i686-w64-mingw32-gcc
AR_i386_windows       := i686-w64-mingw32-ar
CC_loongarch64_linux  := loongarch64-linux-gnu-gcc
AR_loongarch64_linux  := loongarch64-linux-gnu-ar

# ==== 辅助函数 ====
# $(1) = 目标名 (如 scalar-x64_linux)
# 从 .vars.mk 查 FORM_/<grp>/DIST_ 映射
form_of  = $(FORM_$(1))
grp_of   = $(GRP_$(1))
dist_of  = $(DIST_$(1))
# 形态派生
is_win   = $(filter %_windows,$(call form_of,$(1)))
get_cc   = $(CC_$(call form_of,$(1)))
get_ar   = $(AR_$(call form_of,$(1)))
get_flags = $(if $(filter i386_%,$(call form_of,$(1))),$(CFLAGS) -m32,$(if $(filter loongarch64_%,$(call form_of,$(1))),$(LOONGFLAGS),$(CFLAGS)))
get_sfx  = $(if $(call is_win,$(1)),.exe,)
# 每组源文件(默认单文件 src/isb_<grp>.c; 统一构建组也走单入口)
srcs_of  = $(if $(SRCS_$(1)),$(SRCS_$(1)),src/isb_$(1).c)

# ==== 伪目标 ====
.PHONY: all verify-all assemble checksum pack clean

# ==== 顶层目标 ====
all: $(TARGETS)
	@echo "== 全部编译完成 =="

verify-all: $(TARGETS)
	@echo "== 静态核查通过 =="

# ==== 目录创建 ====
dist/bin dist/lib:
	@mkdir -p $@

# ==== per-target 编译规则(通过 secondary expansion 动态解析) ====
.SECONDEXPANSION:

$(TARGETS): $$(call srcs_of,$$(call grp_of,$$@)) $$(HEADERS) | dist/bin dist/lib
	@echo "  [$(call form_of,$@)] $(call get_cc,$@) $(call get_flags,$@) -c ($(words $(call srcs_of,$(call grp_of,$@))) 个源)"
	@rm -f dist/bin/$(call dist_of,$@)_*.o dist/bin/$(call dist_of,$@)$(call get_sfx,$@) dist/lib/$(call dist_of,$@).a
	@for s in $(call srcs_of,$(call grp_of,$@)); do \
	    o=dist/bin/$(call dist_of,$@)_$$(basename $$s .c).o; \
	    $(call get_cc,$@) $(call get_flags,$@) -c $$s -o $$o || exit 1; \
	done
	@$(call get_ar,$@) rcs dist/lib/$(call dist_of,$@).a dist/bin/$(call dist_of,$@)_*.o
	@$(call get_cc,$@) $(call get_flags,$@) dist/bin/$(call dist_of,$@)_*.o -o dist/bin/$(call dist_of,$@)$(call get_sfx,$@) $(LDLIBS)
	@rm -f dist/bin/$(call dist_of,$@)_*.o
	$(call verify_cmd,$(call dist_of,$@),$(call get_ar,$@))

# ==== 静态核查 ====
# $(1) = dist 文件名(scalar_x64_linux), $(2) = ar 命令
define verify_cmd_linux
	@if readelf -l dist/bin/$(1) 2>/dev/null | grep -q INTERP; then echo "!! $(1) 仍带解释器" >&2; exit 1; fi
	@readelf -h dist/bin/$(1) >/dev/null 2>&1 || { echo "!! $(1) 不是有效 ELF" >&2; exit 1; }
	@test -n "$$($(2) t dist/lib/$(1).a 2>/dev/null)" || { echo "!! $(1) 归档为空" >&2; exit 1; }
endef

define verify_cmd_win
	@if objdump -p dist/bin/$(1).exe 2>/dev/null | grep "DLL Name" | grep -viE 'KERNEL32|msvcrt|ntdll|ADVAPI32|GDI32|USER32|SHELL32|WS2_32|ole32|OLEAUT32|RPCRT4|VCRUNTIME'; then echo "!! $(1) 链接了非系统 DLL" >&2; exit 1; fi
	@test -n "$$($(2) t dist/lib/$(1).a 2>/dev/null)" || { echo "!! $(1) 归档为空" >&2; exit 1; }
endef

# $(1) = dist 文件名, $(2) = ar 命令
verify_cmd = $(if $(filter %_windows,$(call form_of,$@)),$(call verify_cmd_win,$(1),$(2)),$(call verify_cmd_linux,$(1),$(2)))

# ==== dist 组装 ====
assemble: 
	@cp -f README.txt dist/README.txt
	@cp -f isbench.py dist/isbench.py
	@cp -f schema.sql dist/schema.sql
	@cp -f group_dict.sql dist/group_dict.sql
	@chmod +x dist/isbench.py 2>/dev/null || true
	@echo "== dist/ 组装完成 =="

# ==== SHA256 ====
# 清单要覆盖 dist 里**全部**要分发的文件(含 assemble 复制的 schema.sql/group_dict.sql
# 与 field_dict.json 等) —— 只列 bin/* lib/* isbench.py README.txt 会让 pack 的
# "包内文件数 = 清单行数+1" 对账凭空差几条(实测踩过: 包内 220 / 清单 216)。
checksum: assemble
	@rm -f dist/SHA256SUMS
	@cd dist && rm -rf results __pycache__ && \
	 find . -type f ! -name SHA256SUMS ! -name '*.pyc' -printf '%P\n' | sort | \
	 xargs -d '\n' sha256sum > SHA256SUMS
	@echo "== SHA256SUMS 已生成 =="
	@ls -la dist/bin/ | head -12
	@echo "   lib/: $(shell ls dist/lib | wc -l) 个归档"

# ==== 打包 ====
pack: checksum
	@rm -rf dist/results dist/__pycache__ 2>/dev/null || true
	@find dist -name '*.pyc' -delete 2>/dev/null || true
	@tar czf isbench-dist.tar.gz --exclude=results --exclude=__pycache__ --exclude='*.pyc' dist
	@n=$$(tar tzf isbench-dist.tar.gz | grep -cE '^dist/bin/[^/]+$$'); \
	 nf=$$(tar tzf isbench-dist.tar.gz | grep -cv '/$$'); \
	 nl=$$(wc -l < dist/SHA256SUMS); \
	 echo "== 打包 isbench-dist.tar.gz: bin=$$n 件 包内文件=$$nf 清单=$$nl 条 =="; \
	 [ "$$n" = "$$(ls dist/bin | wc -l)" ] || { echo "FAIL: bin 件数不等" >&2; exit 1; }; \
	 [ "$$nf" = "$$((nl + 1))" ] || { echo "FAIL: SHA256 对账失败" >&2; exit 1; }

# ==== 清理 ====
clean:
	@rm -rf dist/bin/*.o
	@echo "== 已清理临时 .o =="
