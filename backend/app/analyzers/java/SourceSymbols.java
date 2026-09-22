import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.PrintStream;
import java.util.*;

/** Parse source without resolving dependencies; emit declared AST scopes as JSON lines. */
public class SourceSymbols {
    static String q(String s) {
        if (s == null) return "null";
        StringBuilder b=new StringBuilder("\"");
        for(char c:s.toCharArray()) switch(c) {
            case '"': b.append("\\\"");break; case '\\': b.append("\\\\");break;
            case '\n': b.append("\\n");break;case '\r':b.append("\\r");break;case '\t':b.append("\\t");break;
            default: if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);
        }
        return b.append('"').toString();
    }
    public static void main(String[] args) throws Exception {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();
        if(compiler==null) throw new IllegalStateException("JDK compiler required");
        List<String> files=Files.readAllLines(Path.of(args[0]));
        DiagnosticCollector<JavaFileObject> diagnostics=new DiagnosticCollector<>();
        try(StandardJavaFileManager fm=compiler.getStandardFileManager(diagnostics,null,StandardCharsets.UTF_8)) {
            JavacTask task=(JavacTask)compiler.getTask(null,fm,diagnostics,List.of("-proc:none"),null,fm.getJavaFileObjectsFromStrings(files));
            Iterable<? extends CompilationUnitTree> units=task.parse();
            SourcePositions positions=Trees.instance(task).getSourcePositions();
            for(CompilationUnitTree unit:units) {
                List<String> types=new ArrayList<>(), methods=new ArrayList<>(), fields=new ArrayList<>();
                String pkg=unit.getPackageName()==null?"":unit.getPackageName().toString();
                new TreePathScanner<Void,Void>() {
                    Deque<String> owners=new ArrayDeque<>();
                    long start(Tree t){return positions.getStartPosition(unit,t);}
                    long end(Tree t){return positions.getEndPosition(unit,t);}
                    long line(long p){return unit.getLineMap().getLineNumber(Math.max(0,p));}
                    public Void visitClass(ClassTree t,Void v) {
                        if(t.getSimpleName().length()==0) return null; // anonymous runtime names need debug maps
                        String name=t.getSimpleName().toString();
                        String fqcn=owners.isEmpty()?(pkg.isEmpty()?name:pkg+"."+name):owners.peek()+"$"+name;
                        types.add("{\"name\":"+q(name)+",\"fqcn\":"+q(fqcn)+",\"start\":"+start(t)+",\"end\":"+end(t)+",\"line\":"+line(start(t))+"}");
                        owners.push(fqcn);super.visitClass(t,v);owners.pop();return null;
                    }
                    public Void visitMethod(MethodTree t,Void v) {
                        if(!owners.isEmpty()) methods.add("{\"name\":"+q(t.getName().toString())+",\"owner\":"+q(owners.peek())+",\"start\":"+start(t)+",\"end\":"+end(t)+",\"line\":"+line(start(t))+",\"end_line\":"+line(end(t))+"}");
                        return super.visitMethod(t,v);
                    }
                    public Void visitVariable(VariableTree t,Void v) {
                        TreePath parent=getCurrentPath().getParentPath();
                        if(parent!=null && parent.getLeaf() instanceof ClassTree && !owners.isEmpty()) fields.add("{\"name\":"+q(t.getName().toString())+",\"owner\":"+q(owners.peek())+",\"type\":"+q(t.getType()==null?"":t.getType().toString())+",\"static\":"+t.getModifiers().getFlags().contains(javax.lang.model.element.Modifier.STATIC)+",\"line\":"+line(start(t))+"}");
                        return super.visitVariable(t,v);
                    }
                }.scan(unit,null);
                boolean valid=diagnostics.getDiagnostics().stream().noneMatch(d->d.getKind()==Diagnostic.Kind.ERROR && d.getSource()!=null && d.getSource().toUri().equals(unit.getSourceFile().toUri()));
                System.out.println("{\"path\":"+q(Path.of(unit.getSourceFile().toUri()).toString())+",\"valid\":"+valid+",\"types\":["+String.join(",",types)+"],\"methods\":["+String.join(",",methods)+"],\"fields\":["+String.join(",",fields)+"]}");
            }
        }
    }
}
