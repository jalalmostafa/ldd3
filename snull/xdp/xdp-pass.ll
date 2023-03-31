; ModuleID = 'xdp-pass.c'
source_filename = "xdp-pass.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.xdp_md = type { i32, i32, i32, i32, i32, i32 }

@__const.xdp_prog_simple.____fmt = private unnamed_addr constant [16 x i8] c"bpf_printk: %x\0A\00", align 1
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !0
@llvm.compiler.used = appending global [2 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_prog_simple to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @xdp_prog_simple(%struct.xdp_md* nocapture noundef readonly %0) #0 section "xdp" !dbg !35 {
  %2 = alloca [16 x i8], align 1
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !49, metadata !DIExpression()), !dbg !55
  %3 = getelementptr inbounds [16 x i8], [16 x i8]* %2, i64 0, i64 0, !dbg !56
  call void @llvm.lifetime.start.p0i8(i64 16, i8* nonnull %3) #5, !dbg !56
  call void @llvm.dbg.declare(metadata [16 x i8]* %2, metadata !50, metadata !DIExpression()), !dbg !56
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(16) %3, i8* noundef nonnull align 1 dereferenceable(16) getelementptr inbounds ([16 x i8], [16 x i8]* @__const.xdp_prog_simple.____fmt, i64 0, i64 0), i64 16, i1 false), !dbg !56
  %4 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !56
  %5 = load i32, i32* %4, align 4, !dbg !56, !tbaa !57
  %6 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef nonnull %3, i32 noundef 16, i32 noundef %5) #5, !dbg !56
  call void @llvm.lifetime.end.p0i8(i64 16, i8* nonnull %3) #5, !dbg !62
  ret i32 2, !dbg !63
}

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: argmemonly mustprogress nofree nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly, i8* noalias nocapture readonly, i64, i1 immarg) #3

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #4

attributes #0 = { nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { mustprogress nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { argmemonly mustprogress nofree nosync nounwind willreturn }
attributes #3 = { argmemonly mustprogress nofree nounwind willreturn }
attributes #4 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #5 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!30, !31, !32, !33}
!llvm.ident = !{!34}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 12, type: !27, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, globals: !14, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "xdp-pass.c", directory: "/home/jalal/ldd/snull/xdp", checksumkind: CSK_MD5, checksum: "fbebacaae5345c3c2ca7e3bfdded7808")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 5431, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "", checksumkind: CSK_MD5, checksum: "5ad8bc925dae1ec87bbb04b3148b183b")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2)
!12 = !DIEnumerator(name: "XDP_TX", value: 3)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4)
!14 = !{!0, !15}
!15 = !DIGlobalVariableExpression(var: !16, expr: !DIExpression())
!16 = distinct !DIGlobalVariable(name: "bpf_trace_printk", scope: !2, file: !17, line: 171, type: !18, isLocal: true, isDefinition: true)
!17 = !DIFile(filename: "/usr/include/bpf/bpf_helper_defs.h", directory: "", checksumkind: CSK_MD5, checksum: "eadf4a8bcf7ac4e7bd6d2cb666452242")
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DISubroutineType(types: !20)
!20 = !{!21, !22, !25, null}
!21 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!23 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !24)
!24 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!25 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !26, line: 27, baseType: !7)
!26 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "", checksumkind: CSK_MD5, checksum: "b810f270733e106319b67ef512c6246e")
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 32, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 4)
!30 = !{i32 7, !"Dwarf Version", i32 5}
!31 = !{i32 2, !"Debug Info Version", i32 3}
!32 = !{i32 1, !"wchar_size", i32 4}
!33 = !{i32 7, !"frame-pointer", i32 2}
!34 = !{!"Ubuntu clang version 14.0.0-1ubuntu1"}
!35 = distinct !DISubprogram(name: "xdp_prog_simple", scope: !3, file: !3, line: 6, type: !36, scopeLine: 7, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !48)
!36 = !DISubroutineType(types: !37)
!37 = !{!38, !39}
!38 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 5442, size: 192, elements: !41)
!41 = !{!42, !43, !44, !45, !46, !47}
!42 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !40, file: !6, line: 5443, baseType: !25, size: 32)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !40, file: !6, line: 5444, baseType: !25, size: 32, offset: 32)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !40, file: !6, line: 5445, baseType: !25, size: 32, offset: 64)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !40, file: !6, line: 5447, baseType: !25, size: 32, offset: 96)
!46 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !40, file: !6, line: 5448, baseType: !25, size: 32, offset: 128)
!47 = !DIDerivedType(tag: DW_TAG_member, name: "egress_ifindex", scope: !40, file: !6, line: 5450, baseType: !25, size: 32, offset: 160)
!48 = !{!49, !50}
!49 = !DILocalVariable(name: "ctx", arg: 1, scope: !35, file: !3, line: 6, type: !39)
!50 = !DILocalVariable(name: "____fmt", scope: !51, file: !3, line: 8, type: !52)
!51 = distinct !DILexicalBlock(scope: !35, file: !3, line: 8, column: 5)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 128, elements: !53)
!53 = !{!54}
!54 = !DISubrange(count: 16)
!55 = !DILocation(line: 0, scope: !35)
!56 = !DILocation(line: 8, column: 5, scope: !51)
!57 = !{!58, !59, i64 0}
!58 = !{!"xdp_md", !59, i64 0, !59, i64 4, !59, i64 8, !59, i64 12, !59, i64 16, !59, i64 20}
!59 = !{!"int", !60, i64 0}
!60 = !{!"omnipotent char", !61, i64 0}
!61 = !{!"Simple C/C++ TBAA"}
!62 = !DILocation(line: 8, column: 5, scope: !35)
!63 = !DILocation(line: 9, column: 2, scope: !35)
