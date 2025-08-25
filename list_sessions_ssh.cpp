// list_sessions_ssh.cpp
#include <bits/stdc++.h>
using namespace std;

string run_cmd(const string& cmd) {
    array<char, 4096> buf{};
    string out;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return out;
    while (fgets(buf.data(), buf.size(), pipe)) out.append(buf.data());
    pclose(pipe);
    return out;
}

int main() {
    const vector<string> hosts = {"10.0.109.33", "10.0.109.34"};
    const string user = "oper";
    const string remote_cmd = "vbs_ls";

    // Launch ssh in parallel
    vector<future<string>> futs;
    futs.reserve(hosts.size());
    for (auto& h : hosts) {
        // Uses agent/known_hosts; add "-i ~/.ssh/id_ed25519" if you want a specific key.
        string ssh = "ssh -o BatchMode=yes -o ConnectTimeout=5 " + user + "@" + h +
                     " " + remote_cmd + " 2>/dev/null";
        futs.emplace_back(async(launch::async, run_cmd, ssh));
    }

    set<string> seen;
    vector<string> unique;

    auto process_output = [&](const string& text){
        istringstream iss(text);
        string line;
        while (getline(iss, line)) {
            // strip trailing CR if any
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            auto pos = line.find('_');
            string sess = (pos == string::npos) ? line : line.substr(0, pos);
            if (!sess.empty() && seen.insert(sess).second) unique.push_back(sess);
        }
    };

    for (auto& f : futs) process_output(f.get());

    for (auto& s : unique) cout << s << '\n';
    return 0;
}
