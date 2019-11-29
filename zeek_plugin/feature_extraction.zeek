@load base/protocols/irc/

module IRC_Feature_Extractor;

type IRC_Event: record {
    ts: time &log;
    src: string &log;
    src_ip: addr &log;
    src_port: port &log;
    dst: string &log;
    dst_ip: addr &log;
    dst_port: port &log;
    msg: string &optional &log; 
    msg_size: int &optional &log; 
};

type IRC_Session: record {
    src: string &log;
    src_ip: addr &log;
    src_ports_count: count &log;
    dst: string &log;
    dst_ip: addr &log;
    dst_port: port &log;
    start_time: time &log;
    end_time: time &log;
    duration: double &log;
    msg_count: count &log;
    pkt_size_total: int &log;
    periodicity: double &optional &log;
    spec_chars_username_mean: double &log;
    spec_chars_msg_mean: double &log;
    msg_word_entropy: double &log;
    # malicious: bool;
    msgs: vector of IRC_Event;
};

type IRC_EventKey: record {
    src_ip: addr;
    dst_ip: addr;
    dst_port: port;
};

# LOGGING ENV
export {
    redef enum Log::ID += { LOG };
    
    global log_irc_session: event(rec: IRC_Session);
}

type Complex: record {
    real: double;
    imag: double;
};

type event_vec: vector of IRC_Event;
type double_vec: vector of double;

global irc_logs: vector of IRC_Event = vector();

redef LogAscii::use_json = T;

event zeek_init()
{
    print "zeek init";
    Log::create_stream(IRC_Feature_Extractor::LOG, [$columns=IRC_Session, $path="irc_features"]);
}

event IRC::irc_log(rec: IRC::Info) {
    if (rec$command != "USER") return;
    local ev: IRC_Event = IRC_Event($ts=rec$ts, $src=rec$user, $src_ip=rec$id$orig_h, $src_port=rec$id$orig_p, $dst="", $dst_ip=rec$id$resp_h, $dst_port=rec$id$resp_p, $msg=rec$addl);
    irc_logs += ev;
}

global organize_events: function(): table[IRC_EventKey] of event_vec;
global extract_sessions: function(): vector of IRC_Session;
global argmax_f: function(x: vector of double): count;
global mean_f: function(x:vector of double): double;
global mean_vec_f: function(x: vector of double_vec): vector of double;
global norm_f: function(x: vector of double): double;
global norm_vec_f: function(x: vector of double_vec): double;
global sub_vec_f: function(x_vec: vector of double_vec, y: vector of double): vector of double_vec;
global div_vec_f: function(x: vector of double, y: vector of double): vector of double;
global sum_f: function(x:vector of double): double;
global ln_f: function(x:vector of double): vector of double;
global fft: function(x: vector of Complex): vector of Complex;
global compute_session_periodicity: function(ts_vec: vector of time): double;
global slice_c: function(x: vector of Complex, start: int, step:int): vector of Complex;
global mult_cc: function(a:Complex, b:Complex): Complex;
global mult_cd: function(a:Complex, b:double): Complex;
global exp_c: function(c: Complex): Complex;
global sin: function(x: double): double;
global cos: function(x: double): double;
global cosh: function(x: double): double ;
global sinh: function(x: double): double ;
global pow: function(x:double, p:int): double;
global add_cc: function(a: Complex, b: Complex): Complex;
global sub_cc: function(a: Complex, b:Complex): Complex;
global fft_preprocess_seq: function(x: vector of Complex): vector of Complex;

event zeek_done()
{
    local sessions_vec: vector of IRC_Session = extract_sessions();
    print "zeek done.";
    for (i in sessions_vec ) {
        Log::write( IRC_Feature_Extractor::LOG, sessions_vec[i]);
    }
}

local irc_sessions: vector of IRC_Session;
### FUNCTION HEADERS 
# COMPLEX
local add_cd: function(a: Complex, b: double): Complex;
local div_cc: function(a:Complex, b:Complex): Complex;
local div_cd: function(a:Complex, b:double): Complex;
# UTILS
# MAIN
local get_key: function(ev: IRC_Event): IRC_EventKey;
local extract_features: function(out:file);


### FUNCTION IMPLEMENTATION
extract_sessions = function(): vector of IRC_Session
{
    print "extract sessions...";
    local events: table[IRC_EventKey] of event_vec = organize_events();
    local session_vec: vector of IRC_Session;
    local i_count :count  = 0;
    for (i in events) {
        print "######################################";
        print "#session: ",i_count+1,"/",|events|;
        local ev: IRC_Event = events[i][0];
        local src: string = ev$src;
        print "src: ", src;
        local src_ip: addr = ev$src_ip;
        print "src IP: ", src_ip;
        local start_time: time = ev$ts;
        print "start time: ", start_time;
        local last_msg_idx: count = |events[i]| - 1;
        local end_time: time = events[i][last_msg_idx]$ts;
        print "end time: ", start_time;
        local dst: string = ev$dst;
        print "dst: ", dst;
        local dst_ip: addr = ev$dst_ip;
        print "dst IP: ", dst_ip;
        local dst_port: port = ev$dst_port;

        local pkt_size_total: int = -1; # TODO
        local msg_ts_vec: vector of time;
        local msg_count: count = |events[i]|;
        print "msg_count: ", msg_count;
        local word_occurency_table: table[string] of count;

        local _spec_chars_username_rgx: PatternMatchResult = match_pattern(src, /[^A-Za-z]/);
        local spec_chars_username_mean: double = |_spec_chars_username_rgx$str| / |src|;
        local msg_special_chars: vector of double;
        local src_ports: set[port];
        for (j in events[i])
        {
            local ev2: IRC_Event = events[i][j];
            msg_ts_vec += ev2$ts;
            local msg: string = ev2$msg;
            local split_msg: string_vec = split_string(msg,/ /);
            
            # compute word occurency
            for (k in split_msg) {
                local w: string = split_msg[k];
                if (w in word_occurency_table) {
                    word_occurency_table[w] += 1;
                } else {
                    word_occurency_table[w] = 1;
                }
            }

            # compute msg special chars
            local _msg_spec_rgx: PatternMatchResult = match_pattern(msg, /[^A-Za-z]/);
            local msg_spec: double = |_msg_spec_rgx$str| / |msg|;
            msg_special_chars += msg_spec;
            add src_ports[ev2$src_port];   
        }

        # compute msg word entropy
        local word_count_sum: count = 0;
        local word_count: count = |word_occurency_table|;
        local p: vector of double;

        local c: count;
        local word: string;
        for (word, c in word_occurency_table)
        {
            p += c;
            word_count_sum += c;
        }
        p = p / word_count_sum;

        # compute msg special chars mean
        local spec_chars_msg_mean: double = mean_f(msg_special_chars);
        print "special characters message mean: ", spec_chars_msg_mean;
        local msg_word_entropy: double = -sum_f(p * (ln_f(p)/ln(2)));
        print "message word entropy: ", msg_word_entropy;
        local duration: double = interval_to_double(end_time - start_time);
        print "duration: ", duration;
        local periodicity: double = compute_session_periodicity(msg_ts_vec);
        print "periodicity: ", periodicity;
        local session: IRC_Session = IRC_Session($src = src, $src_ip = src_ip, $src_ports_count = |src_ports|,$dst = dst,$dst_ip = dst_ip,
            $dst_port = dst_port, 
            $start_time = start_time, 
            $end_time = end_time, 
            $duration = duration, 
            $msg_count = msg_count, 
            $pkt_size_total = pkt_size_total, # TODO
            $spec_chars_username_mean = spec_chars_username_mean,
            $spec_chars_msg_mean = spec_chars_msg_mean,
            $msg_word_entropy = msg_word_entropy,
            $msgs = events[i]
            );
        if (periodicity != -1) {
            session$periodicity = periodicity;
        }
        session_vec += session;
        i_count += 1;
    }
    return session_vec;
};


organize_events = function(): table[IRC_EventKey] of event_vec
{
    print "organize events...";
    print "|events|: ", |irc_logs|;
    local key_set: table[IRC_EventKey] of event_vec;
    for (i in irc_logs) {
        local ev: IRC_Event = irc_logs[i];
        # create a session and for loop the rest of the logs and add which is matching by the key  and create 'array of arrays'
        local src_ip: addr = ev$src_ip;
        local dst_ip: addr = ev$dst_ip;
        local dst_port: port = ev$dst_port;
        local ev_key: IRC_EventKey = IRC_EventKey($src_ip = src_ip, $dst_ip = dst_ip, $dst_port = dst_port);
        if (ev_key in key_set) {
            local vv: event_vec = key_set[ev_key];
            vv += ev;
            key_set[ev_key] = vv;
        } else {
            local vv2: event_vec = vector(ev);
            key_set[ev_key] = vv2;
        }
    }
    return key_set;
}; 

compute_session_periodicity = function(ts_vec: vector of time): double
{
    print "compute_session_periodicity...";

    if (|ts_vec| < 3) {
        return -1;
    }

    local ts_vecsize: count = |ts_vec|;
    local time_diff_vec: vector of double; 
    local td_vec: vector of double;
    local td_vec_c: vector of Complex;
    for (i in ts_vec)
    {
        if (i+1 == ts_vecsize) break;
        local td: double = interval_to_double(ts_vec[i+1] - ts_vec[i]);
        td_vec += td;
        td_vec_c += Complex($real=td, $imag=0);
    }

    if (|td_vec_c| > 0) {
        local td_vec_c2: vector of Complex = fft_preprocess_seq(td_vec_c);
        print "fft...";
        local per_vec: vector of Complex = fft(td_vec_c2);
    }

    local per_vec_real: vector of double;

    for (i in per_vec)
    {
        per_vec_real += per_vec[i]$real;
    }

    local t: count = argmax_f(per_vec_real) + 2;
    local rng_size: count = |td_vec|;
    local td_T: vector of double_vec = vector();

    local x: count = 0;
    local x_idx: count;
    local x_start: count;
    local x_end: count;
    
    print "dividing td into boxes....";
    while (x*t+t <= rng_size) { 
        local x_vec: vector of double = vector();
        x_start = x * t;
        x_end = x * t + t;
        x_idx = x_start;
        while (x_idx != x_end) {
            x_vec += td_vec[x_idx];
            x_idx += 1;
        }
        td_T += x_vec;
        x += 1;
    }

    local td_T_avg: vector of double = mean_vec_f(td_T);
    local td_T_norm: double = norm_vec_f(td_T);
    local td_T_sub: vector of double_vec = sub_vec_f(td_T, td_T_avg);
    local td_T_sub_norm: double = norm_vec_f(td_T_sub);
    local td_nmse: double = td_T_sub_norm / td_T_norm;
    return 1 - td_nmse;
};


# fast fourier transform
fft = function(x: vector of Complex): vector of Complex 
{
    # print "fft..";
    local N: count = |x|;
    if (N <= 1) return x;
    local x_odd: vector of Complex = slice_c(x, 0, 2);
    local x_even: vector of Complex = slice_c(x, 1, 2);
    local fft_even: vector of Complex = fft(x_even);
    local fft_odd: vector of Complex = fft(x_odd);

    local T_vec: vector of Complex = vector();
    local nn: int =  N/2;
    local pi: double = 3.14159265;
    local c: Complex = Complex($real=0, $imag=-2);
    local k: int = 0;
    
    while (k != nn)
    {
        local tmp_d: double = pi * k/N;
        local c2: Complex = mult_cd(c, tmp_d);
        local c3: Complex = exp_c(c2);
        T_vec += mult_cc(c3,fft_odd[k]);
        k += 1;
    }

    local res: vector of Complex = vector();
    local k2: count = 0;
    while (k2 != nn)
    {
        res += add_cc(fft_even[k2], T_vec[k2]);
        k2 += 1; 
    }
    
    local k3: count = 0;
    while (k3 != nn)
    {
        res += sub_cc(fft_even[k3], T_vec[k3]);
        k3 += 1;
    }

    return res;
};


fft_preprocess_seq = function(x: vector of Complex): vector of Complex 
{

    local x_len: int = |x|;
    local x_new: vector of Complex = vector();
    local x_pow: int = ln(x_len)/ln(2);
    local x_len_new : double = pow(2,x_pow);
    local i: count = 0;
    while (i < x_len_new) 
    {
        x_new += x[i];
        i += 1;
    }
    return x_new;
};

# ## COMPLEX 
add_cc = function(a: Complex, b: Complex): Complex
{
    # print "add_cc";
    local r: double = a$real + b$real;
    local i: double = a$imag + b$imag;
    local c: Complex = Complex($real=r, $imag=i);
    return c;
};

sub_cc = function(a: Complex, b:Complex): Complex
{
    # print "sub_cc";
    local r: double = a$real - b$real;
    local i: double = a$imag - b$imag;
    local c: Complex = Complex($real=r, $imag=i);
    return c;
};

mult_cc = function(a:Complex, b:Complex): Complex
{
    # print "mult_cc";
    local r: double = a$real * b$real - a$imag * b$imag;
    local i: double = a$imag * b$real + a$real * b$imag;
    local c: Complex = Complex($real=r, $imag=i);
    return c;
};

mult_cd = function(a:Complex, b:double): Complex
{
    # print "mult_cd";
    local r: double = a$real * b;
    local i: double = a$imag *b;
    local c: Complex = Complex($real=r, $imag=i);
    return c;
};

cosh = function(x: double): double
{
    # print "cosh";
    local r: double = (exp(x) + exp(-x))/2;
    return r;
};

sinh = function(x: double): double
{
    # print "sinh";
    local r: double = (exp(x) - exp(-x))/2;
    return r;
};

sin = function(x: double): double
{
    # print "sin";
    local a: double = x;
    local s: double = a;
    local i:count = 1;
    while (i != 100) {
        local a_c: double =  -1 * pow(x,2);
        local a_j: double  = (2 * i) * (2 * i + 1);
        a = a * (a_c / a_j);
        s += a;
        i += 1;
    }
    return s;
};

cos = function(x: double): double
{
    # print "cos";
    local offset: double = 3.14159265/2.0;
    return sin(x+offset);
};

exp_c = function(c: Complex) : Complex
{
    # print "exp_C";
    local r: double = cosh(c$real) + sinh(c$real);
    local imcos: double = cos(c$imag);
    local imsin: double = sin(c$imag);
    local cc: Complex = Complex($real=imcos, $imag=imsin);
    local cc2: Complex = mult_cd(cc, r);
    return cc2;
};

# # assumptions: step > 0, |x| >= start >= 0,  end = |x|
# # TODO: test the correctness
slice_c = function(x: vector of Complex, start: int, step:int): vector of Complex
{
    # print "slice_c";
    local slice_x: vector of Complex = vector();
    for (i in x) {
        if (i >= start && (i-start) % step == 0) {
            slice_x += x[i];
        }
    }
    return slice_x;
};
# ## UTILS
pow = function(x:double, p:int) : double {
    # print "pow";
    local x_p: double = x;
    local i: count = 0;
    while (i != p-1)
    {
        x_p = x_p*x;
        i += 1;
    }
    return x_p;
};

sub_vec_f = function(x_vec: vector of double_vec, y: vector of double): vector of double_vec {
    for (i in x_vec) {
        for (j in y) {
            x_vec[i][j] -= y[j];
        }
    }
    return x_vec;
};

div_vec_f = function(x: vector of double, y: vector of double): vector of double {
    local div_vec: vector of double = vector();
    for (i in x) {
        div_vec += x[i] / y[i];
    }
    return div_vec;
};

norm_f = function(x: vector of double): double {
    local norm_sq: double = 0;
    for (i in x) {
        norm_sq += x[i]*x[i];
    }
    local norm: double = sqrt(norm_sq);
    return norm;
};

norm_vec_f = function(x: vector of double_vec): double {
    local i: int = 0;
    local j: int = 0;
    local norm: double = 0;
    
    local x_len: int = |x|;
    local x0_len: int = |x[0]|;
    local v: vector of double = vector();
    while (i < x0_len) {
        # print i, "/", x0_len;
        v = vector();
        j = 0;
        while (j < x_len) {
            v += x[j][i];
            j += 1;
        }
        norm += norm_f(v);
        i += 1;
    }
    
    return norm;
};

mean_vec_f = function(x: vector of double_vec): vector of double {
    local i: int = 0;
    local j: int;
    local mean_vec: vector of double = vector();
    local v: vector of double = vector();
    local vi: vector of double = vector();

    local x_len: int = |x|;
    local x0_len: int = |x[0]|;
    while (i < x0_len) {
        # print i, "/", x0_len;
        v = vector();
        j = 0;
        while (j < x_len) {
            v += x[j][i];
            j += 1;
        }
        mean_vec += mean_f(v);
        i += 1;
    }
    
    return mean_vec;
};

sum_f = function(x:vector of double): double {
    # print "add_cc";
    local sum_r: double = 0;
    for (i in x)
    {
        sum_r += x[i];
    }
    return sum_r;
};

mean_f = function(x:vector of double): double {
    # print "mean_f...";
    return sum_f(x) / |x|;
};

ln_f = function(x:vector of double): vector of double {
    # print "ln_f";
    local ln_vec: vector of double;
    for (i in x) {
        ln_vec += ln(x[i]);
    }
    return ln_vec;
};

argmax_f = function(x: vector of double): count {
    local max_idx: count;
    local max_val: double;
    max_val = -9999;
    for (i in x) {
        if (x[i] > max_val){
            max_idx = i;
            max_val = x[i];
        }
    }
    return max_idx;
};