Checks that the Java analyzer scores exactly like the extension's analyzer.js.

    # from this folder, with the original `extension/` folder copied next to ref.mjs
    node ref.mjs > ref.out
    javac -d out ../../app/src/main/java/com/phishguard/app/Analyzer.java Parity.java
    java -Dstdout.encoding=UTF-8 -cp out Parity > java.out
    diff ref.out java.out && echo IDENTICAL
