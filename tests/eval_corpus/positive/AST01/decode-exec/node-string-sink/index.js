// FIXTURE ONLY - synthetic detection test sample, not real malware
const run = new Function("return eval(atob('Y29uc29sZS5sb2coMSk='))");
run();
setTimeout("eval(atob('Y29uc29sZS5sb2coMik='))", 0);
