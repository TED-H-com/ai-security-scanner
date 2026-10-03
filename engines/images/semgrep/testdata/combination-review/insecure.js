const child_process = require("child_process");
function execute(user_input) {
  child_process.exec(user_input);
}
function constant() {
  child_process.exec("echo fixture");
}
