// vigil-gui — GTK4 front-end for the Vigil post-quantum file-integrity monitor.
//
// This is a thin, friendly face over the `vigil` command-line tool: it builds
// the right argument vector for each operation, runs the binary, and streams its
// output live into an activity log. Everything it can do, the CLI can do — the
// GUI never reimplements any crypto or scanning, it just drives `vigil`.
//
// Pages:
//   * Keygen   — create a passphrase-protected ML-DSA keypair
//   * Baseline — record a signed baseline of a directory tree
//   * Check    — compare a tree against a baseline (one-shot)
//   * Watch    — live, incremental monitoring; long-running, so it can be
//                minimized/closed to the system tray
//   * Inspect  — verify a baseline's signature, or show its contents
//
// GTK4 / C++17, dark "post-quantum" theme. The tray + minimize/close-to-tray
// behaviour matches Warden (see tray.cpp).
//
// Author: Jean-Francois Lachance-Caumartin
// Repository: https://github.com/effjy/vigil/

#include <gtk/gtk.h>
#include <gio/gio.h>
#ifdef GDK_WINDOWING_X11
#include <gdk/x11/gdkx.h>   // raise-to-front from the tray (see present_front)
#endif

#include <libgen.h>
#include <unistd.h>
#include <limits.h>

#include <string>
#include <vector>
#include <sstream>

#include "tray.h"

#ifndef VIGIL_VERSION
#define VIGIL_VERSION "0.0.0"
#endif

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------
struct App {
    GtkApplication *app    = nullptr;
    GtkWidget *window      = nullptr;
    GtkWidget *status_lbl  = nullptr;
    GtkWidget *log_view    = nullptr;
    GtkTextMark *log_end   = nullptr;
    GtkWidget *stop_btn    = nullptr;
    GtkWidget *stack       = nullptr;
    std::vector<GtkWidget*> run_btns;   // disabled while a command runs

    std::string vigil_bin;              // resolved path to the `vigil` binary

    // Running child process (at most one at a time).
    GSubprocess     *proc    = nullptr;
    GDataInputStream*dstream = nullptr;
    GCancellable    *cancel  = nullptr;
    bool             is_watch = false;

    bool        tray_active = false;

    // --- page widgets -------------------------------------------------------
    // Keygen
    GtkWidget *kg_alg, *kg_key, *kg_pub, *kg_pass, *kg_pass2;
    // Baseline
    GtkWidget *bl_path, *bl_key, *bl_out, *bl_excl, *bl_pass;
    // Check
    GtkWidget *ck_path, *ck_pub, *ck_db, *ck_quiet;
    // Watch
    GtkWidget *wt_path, *wt_pub, *wt_db;
    // Inspect
    GtkWidget *in_pub, *in_db, *in_list;
};

// ---------------------------------------------------------------------------
// Activity log
// ---------------------------------------------------------------------------
static void log_raw(App *app, const std::string &line, const char *css = nullptr) {
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->log_view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    if (css) {
        gtk_text_buffer_insert_with_tags_by_name(buf, &end, (line + "\n").c_str(), -1, css, nullptr);
    } else {
        gtk_text_buffer_insert(buf, &end, (line + "\n").c_str(), -1);
    }
    if (app->log_end)
        gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(app->log_view),
                                     app->log_end, 0.0, TRUE, 0.0, 1.0);
}

// A timestamped section header announcing the command being run.
static void log_cmd(App *app, const std::string &title) {
    char t[32]; time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm);
    strftime(t, sizeof(t), "%H:%M:%S", &tm);
    log_raw(app, std::string("[") + t + "]  " + title, "hdr");
}

static void set_status(App *app, const char *text, const char *css_class) {
    gtk_label_set_text(GTK_LABEL(app->status_lbl), text);
    gtk_widget_remove_css_class(app->status_lbl, "ok");
    gtk_widget_remove_css_class(app->status_lbl, "bad");
    gtk_widget_remove_css_class(app->status_lbl, "busy");
    gtk_widget_add_css_class(app->status_lbl, css_class);
}

// ---------------------------------------------------------------------------
// Running the vigil binary and streaming its output
// ---------------------------------------------------------------------------
static void set_busy(App *app, bool busy) {
    for (GtkWidget *b : app->run_btns) gtk_widget_set_sensitive(b, !busy);
    gtk_widget_set_sensitive(app->stop_btn, busy);
}

static void read_next_line(App *app);

static void on_proc_done(GObject *src, GAsyncResult *res, gpointer data) {
    App *app = (App *)data;
    g_subprocess_wait_finish(G_SUBPROCESS(src), res, nullptr);

    GSubprocess *p = G_SUBPROCESS(src);
    if (g_subprocess_get_if_exited(p)) {
        int code = g_subprocess_get_exit_status(p);
        // vigil's exit codes: 0 ok, 2 drift, 4 bad signature, 1 error.
        switch (code) {
            case 0: log_raw(app, "— done (clean / success)", "ok");
                    set_status(app, "Done — success", "ok"); break;
            case 2: log_raw(app, "— drift detected (exit 2)", "warn");
                    set_status(app, "Drift detected", "bad"); break;
            case 4: log_raw(app, "— BAD SIGNATURE (exit 4) — baseline not trusted", "bad");
                    set_status(app, "Bad signature", "bad"); break;
            default: log_raw(app, "— finished with error (exit " + std::to_string(code) + ")", "bad");
                    set_status(app, "Error", "bad"); break;
        }
    } else {
        log_raw(app, "— stopped", "warn");
        set_status(app, "Stopped", "busy");
    }
    log_raw(app, "", nullptr);

    if (app->dstream) { g_object_unref(app->dstream); app->dstream = nullptr; }
    if (app->cancel)  { g_object_unref(app->cancel);  app->cancel  = nullptr; }
    if (app->proc)    { g_object_unref(app->proc);    app->proc    = nullptr; }
    app->is_watch = false;
    set_busy(app, false);
}

static void on_line(GObject *src, GAsyncResult *res, gpointer data) {
    App *app = (App *)data;
    gsize len = 0; GError *err = nullptr;
    char *line = g_data_input_stream_read_line_finish(G_DATA_INPUT_STREAM(src), res, &len, &err);
    if (line) {
        // Tint lines by their leading drift marker so the log reads at a glance.
        const char *css = nullptr;
        if      (line[0] == '+') css = "ok";
        else if (line[0] == '-') css = "bad";
        else if (line[0] == '~') css = "warn";
        else if (line[0] == '=') css = "dim";
        else if (strstr(line, "\xe2\x9c\x93")) css = "ok";   // ✓
        else if (strstr(line, "\xe2\x9c\x97")) css = "bad";  // ✗
        else if (strstr(line, "\xe2\x9a\xa0")) css = "warn"; // ⚠
        log_raw(app, line, css);
        g_free(line);
        read_next_line(app);
    } else {
        if (err) g_error_free(err);
        // EOF: the wait_async callback (on_proc_done) reports the exit code.
    }
}

static void read_next_line(App *app) {
    if (!app->dstream) return;
    g_data_input_stream_read_line_async(app->dstream, G_PRIORITY_DEFAULT,
                                        app->cancel, on_line, app);
}

// Spawn `vigil <args...>`. If `passphrase` is non-null it is passed through the
// VIGIL_PASSPHRASE environment variable so the child never needs a TTY.
static void run_vigil(App *app, const std::vector<std::string> &args,
                      const std::string &title, const char *passphrase,
                      bool is_watch) {
    if (app->proc) { log_raw(app, "A command is already running.", "warn"); return; }

    GSubprocessLauncher *l = g_subprocess_launcher_new(
        (GSubprocessFlags)(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE));
    g_subprocess_launcher_setenv(l, "NO_COLOR", "1", TRUE);
    if (passphrase)
        g_subprocess_launcher_setenv(l, "VIGIL_PASSPHRASE", passphrase, TRUE);

    std::vector<const char*> argv;
    argv.push_back(app->vigil_bin.c_str());
    for (const auto &a : args) argv.push_back(a.c_str());
    argv.push_back(nullptr);

    GError *err = nullptr;
    GSubprocess *p = g_subprocess_launcher_spawnv(l, argv.data(), &err);
    g_object_unref(l);
    if (!p) {
        log_raw(app, std::string("failed to launch vigil: ") + (err ? err->message : "?"), "bad");
        if (err) g_error_free(err);
        return;
    }

    // Echo the command line (helpful + makes the GUI self-documenting).
    std::string shown = "vigil";
    for (const auto &a : args) shown += " " + a;
    log_cmd(app, title);
    log_raw(app, std::string("$ ") + shown, "dim");

    app->proc = p;
    app->is_watch = is_watch;
    app->cancel = g_cancellable_new();
    GInputStream *out = g_subprocess_get_stdout_pipe(p);
    app->dstream = g_data_input_stream_new(out);
    set_busy(app, true);
    set_status(app, is_watch ? "Watching…" : "Running…", "busy");
    g_subprocess_wait_async(p, nullptr, on_proc_done, app);
    read_next_line(app);
}

static void on_stop_clicked(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (app->proc) {
        if (app->cancel) g_cancellable_cancel(app->cancel);
        g_subprocess_force_exit(app->proc);
        log_raw(app, "Stopping…", "warn");
    }
}

// ---------------------------------------------------------------------------
// Small widget helpers
// ---------------------------------------------------------------------------
static const char *entry_text(GtkWidget *e) { return gtk_editable_get_text(GTK_EDITABLE(e)); }

static bool empty(GtkWidget *e) { const char *t = entry_text(e); return !t || !*t; }

// A label + entry row, optionally with a "Browse…" button. mode: 0 none,
// 1 open-file, 2 save-file, 3 open-folder.
struct PickCtx { App *app; GtkWidget *entry; int mode; };

static void on_pick_done(GObject *src, GAsyncResult *res, gpointer data) {
    PickCtx *pc = (PickCtx *)data;
    GError *err = nullptr;
    GFile *f = (pc->mode == 3)
        ? gtk_file_dialog_select_folder_finish(GTK_FILE_DIALOG(src), res, &err)
        : (pc->mode == 2)
            ? gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, &err)
            : gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, &err);
    if (f) {
        char *path = g_file_get_path(f);
        if (path) { gtk_editable_set_text(GTK_EDITABLE(pc->entry), path); g_free(path); }
        g_object_unref(f);
    }
    if (err) g_error_free(err);
    g_free(pc);
}

static void on_browse(GtkButton *btn, gpointer data) {
    PickCtx *base = (PickCtx *)data;
    GtkFileDialog *d = gtk_file_dialog_new();
    const char *cur = entry_text(base->entry);
    if (cur && *cur) {
        GFile *f = g_file_new_for_path(cur);
        if (base->mode == 3) gtk_file_dialog_set_initial_folder(d, f);
        else                 gtk_file_dialog_set_initial_file(d, f);
        g_object_unref(f);
    }
    PickCtx *pc = g_new0(PickCtx, 1); *pc = *base;
    GtkWidget *win = gtk_widget_get_ancestor(GTK_WIDGET(btn), GTK_TYPE_WINDOW);
    if (base->mode == 3)
        gtk_file_dialog_select_folder(d, GTK_WINDOW(win), nullptr, on_pick_done, pc);
    else if (base->mode == 2)
        gtk_file_dialog_save(d, GTK_WINDOW(win), nullptr, on_pick_done, pc);
    else
        gtk_file_dialog_open(d, GTK_WINDOW(win), nullptr, on_pick_done, pc);
    g_object_unref(d);
}

// Append a "label: [entry] [Browse]" row to a vertical box; returns the entry.
static GtkWidget *add_row(App *app, GtkWidget *box, const char *label,
                          const char *placeholder, int browse_mode) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *lbl = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_widget_set_size_request(lbl, 130, -1);
    gtk_widget_add_css_class(lbl, "field");
    GtkWidget *entry = gtk_entry_new();
    if (placeholder) gtk_entry_set_placeholder_text(GTK_ENTRY(entry), placeholder);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_box_append(GTK_BOX(row), lbl);
    gtk_box_append(GTK_BOX(row), entry);
    if (browse_mode) {
        GtkWidget *b = gtk_button_new_with_label("Browse…");
        PickCtx *pc = g_new0(PickCtx, 1); pc->app = app; pc->entry = entry; pc->mode = browse_mode;
        g_signal_connect_data(b, "clicked", G_CALLBACK(on_browse), pc,
                              [](gpointer d, GClosure *) { g_free(d); }, (GConnectFlags)0);
        gtk_box_append(GTK_BOX(row), b);
    }
    gtk_box_append(GTK_BOX(box), row);
    return entry;
}

static GtkWidget *page_box(void) {
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(b, 14); gtk_widget_set_margin_bottom(b, 14);
    gtk_widget_set_margin_start(b, 16); gtk_widget_set_margin_end(b, 16);
    return b;
}

static GtkWidget *page_intro(const char *text) {
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_widget_add_css_class(l, "intro");
    return l;
}

static GtkWidget *action_button(App *app, GtkWidget *box, const char *label,
                                GCallback cb) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_START);
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_widget_add_css_class(b, "go");
    g_signal_connect(b, "clicked", cb, app);
    app->run_btns.push_back(b);
    gtk_box_append(GTK_BOX(row), b);
    gtk_box_append(GTK_BOX(box), row);
    return b;
}

// Split a free-form exclude string ("proc sys *.log") into separate patterns.
static std::vector<std::string> split_ws(const std::string &s) {
    std::vector<std::string> out; std::istringstream is(s); std::string w;
    while (is >> w) out.push_back(w);
    return out;
}

// ---------------------------------------------------------------------------
// Page actions
// ---------------------------------------------------------------------------
static void do_keygen(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (empty(app->kg_key) || empty(app->kg_pub)) {
        log_raw(app, "keygen: secret-key and public-key paths are required.", "bad"); return;
    }
    std::string p1 = entry_text(app->kg_pass), p2 = entry_text(app->kg_pass2);
    if (p1.empty())  { log_raw(app, "keygen: a passphrase is required.", "bad"); return; }
    if (p1 != p2)    { log_raw(app, "keygen: passphrases do not match.", "bad"); return; }

    const char *alg = gtk_string_object_get_string(
        GTK_STRING_OBJECT(gtk_drop_down_get_selected_item(GTK_DROP_DOWN(app->kg_alg))));
    std::vector<std::string> a = { "keygen", "-a", alg,
        "-k", entry_text(app->kg_key), "-p", entry_text(app->kg_pub) };
    run_vigil(app, a, "Generating keypair", p1.c_str(), false);
}

static void do_baseline(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (empty(app->bl_path)) { log_raw(app, "baseline: choose a directory to baseline.", "bad"); return; }
    if (empty(app->bl_key))  { log_raw(app, "baseline: a secret key is required.", "bad"); return; }
    if (empty(app->bl_out))  { log_raw(app, "baseline: an output file is required.", "bad"); return; }
    std::string pass = entry_text(app->bl_pass);
    if (pass.empty())        { log_raw(app, "baseline: the key passphrase is required.", "bad"); return; }

    std::vector<std::string> a = { "baseline", entry_text(app->bl_path),
        "-k", entry_text(app->bl_key), "-o", entry_text(app->bl_out) };
    for (const auto &g : split_ws(entry_text(app->bl_excl))) { a.push_back("-x"); a.push_back(g); }
    run_vigil(app, a, "Creating signed baseline", pass.c_str(), false);
}

static void do_check(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (empty(app->ck_pub) || empty(app->ck_db)) {
        log_raw(app, "check: a public key and a baseline file are required.", "bad"); return;
    }
    std::vector<std::string> a = { "check" };
    if (!empty(app->ck_path)) a.push_back(entry_text(app->ck_path));
    a.push_back("-p"); a.push_back(entry_text(app->ck_pub));
    a.push_back("-d"); a.push_back(entry_text(app->ck_db));
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(app->ck_quiet))) a.push_back("--quiet");
    run_vigil(app, a, "Checking tree against baseline", nullptr, false);
}

static void do_watch(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (empty(app->wt_pub) || empty(app->wt_db)) {
        log_raw(app, "watch: a public key and a baseline file are required.", "bad"); return;
    }
    std::vector<std::string> a = { "watch" };
    if (!empty(app->wt_path)) a.push_back(entry_text(app->wt_path));
    a.push_back("-p"); a.push_back(entry_text(app->wt_pub));
    a.push_back("-d"); a.push_back(entry_text(app->wt_db));
    run_vigil(app, a, "Watching tree (live)", nullptr, true);
    if (app->tray_active)
        log_raw(app, "Tip: minimize or close the window to keep watching from the tray.", "dim");
}

static void do_verify(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (empty(app->in_pub) || empty(app->in_db)) {
        log_raw(app, "verify: a public key and a baseline file are required.", "bad"); return;
    }
    std::vector<std::string> a = { "verify", "-p", entry_text(app->in_pub),
                                   "-d", entry_text(app->in_db) };
    run_vigil(app, a, "Verifying signature", nullptr, false);
}

static void do_show(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (empty(app->in_db)) { log_raw(app, "show: a baseline file is required.", "bad"); return; }
    std::vector<std::string> a = { "show", "-d", entry_text(app->in_db) };
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(app->in_list))) a.push_back("--list");
    run_vigil(app, a, "Inspecting baseline", nullptr, false);
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------
static GtkWidget *build_keygen_page(App *app) {
    GtkWidget *box = page_box();
    gtk_box_append(GTK_BOX(box), page_intro(
        "Create a passphrase-protected ML-DSA keypair. The secret key is "
        "encrypted at rest (Argon2id + AES-256-GCM) — keep it (and its "
        "passphrase) offline."));

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *lbl = gtk_label_new("Algorithm");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_widget_set_size_request(lbl, 130, -1);
    gtk_widget_add_css_class(lbl, "field");
    const char *algs[] = { "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", nullptr };
    app->kg_alg = gtk_drop_down_new_from_strings(algs);
    gtk_drop_down_set_selected(GTK_DROP_DOWN(app->kg_alg), 1);  // ml-dsa-65 default
    gtk_box_append(GTK_BOX(row), lbl);
    gtk_box_append(GTK_BOX(row), app->kg_alg);
    // Keep the action on the algorithm row (right-aligned) so the page stays
    // short and never runs off the bottom of small displays.
    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(row), spacer);
    GtkWidget *gen = gtk_button_new_with_label("Generate keypair");
    gtk_widget_add_css_class(gen, "go");
    g_signal_connect(gen, "clicked", G_CALLBACK(do_keygen), app);
    app->run_btns.push_back(gen);
    gtk_box_append(GTK_BOX(row), gen);
    gtk_box_append(GTK_BOX(box), row);

    app->kg_key  = add_row(app, box, "Secret key file", "vigil.key", 2);
    app->kg_pub  = add_row(app, box, "Public key file", "vigil.pub", 2);
    app->kg_pass = add_row(app, box, "Passphrase", "choose a strong passphrase", 0);
    gtk_entry_set_visibility(GTK_ENTRY(app->kg_pass), FALSE);
    app->kg_pass2 = add_row(app, box, "Confirm passphrase", "repeat passphrase", 0);
    gtk_entry_set_visibility(GTK_ENTRY(app->kg_pass2), FALSE);
    return box;
}

static GtkWidget *build_baseline_page(App *app) {
    GtkWidget *box = page_box();
    gtk_box_append(GTK_BOX(box), page_intro(
        "Scan a directory tree, hash every file, and write a signed baseline "
        "(.vgl). Requires the secret key. Excludes are space-separated globs "
        "(e.g. proc sys *.log) and are stored in the signed baseline."));

    app->bl_path = add_row(app, box, "Directory", "/path/to/watch", 3);
    app->bl_key  = add_row(app, box, "Secret key", "vigil.key", 1);
    app->bl_out  = add_row(app, box, "Output baseline", "baseline.vgl", 2);
    app->bl_excl = add_row(app, box, "Exclude globs", "optional: proc sys *.log", 0);
    app->bl_pass = add_row(app, box, "Key passphrase", "passphrase for the secret key", 0);
    gtk_entry_set_visibility(GTK_ENTRY(app->bl_pass), FALSE);

    action_button(app, box, "Create baseline", G_CALLBACK(do_baseline));
    return box;
}

static GtkWidget *build_check_page(App *app) {
    GtkWidget *box = page_box();
    gtk_box_append(GTK_BOX(box), page_intro(
        "Verify the baseline's signature, then re-scan the tree and report what "
        "was added, removed or modified. Only the public key is needed. Leave "
        "the directory blank to use the baseline's recorded root."));

    app->ck_path = add_row(app, box, "Directory", "(blank = baseline's root)", 3);
    app->ck_pub  = add_row(app, box, "Public key", "vigil.pub", 1);
    app->ck_db   = add_row(app, box, "Baseline file", "baseline.vgl", 1);
    app->ck_quiet = gtk_check_button_new_with_label("Quiet (summary only)");
    gtk_box_append(GTK_BOX(box), app->ck_quiet);

    action_button(app, box, "Check now", G_CALLBACK(do_check));
    return box;
}

static GtkWidget *build_watch_page(App *app) {
    GtkWidget *box = page_box();
    gtk_box_append(GTK_BOX(box), page_intro(
        "Live, incremental monitoring via inotify. Drift events stream into the "
        "log below as they happen. For long watches you can minimize or close "
        "the window to the system tray — Vigil keeps watching in the background. "
        "Use Stop (top-right) to end the watch."));

    app->wt_path = add_row(app, box, "Directory", "(blank = baseline's root)", 3);
    app->wt_pub  = add_row(app, box, "Public key", "vigil.pub", 1);
    app->wt_db   = add_row(app, box, "Baseline file", "baseline.vgl", 1);

    action_button(app, box, "Start watching", G_CALLBACK(do_watch));
    return box;
}

static GtkWidget *build_inspect_page(App *app) {
    GtkWidget *box = page_box();
    gtk_box_append(GTK_BOX(box), page_intro(
        "Verify a baseline's ML-DSA signature without touching the filesystem, "
        "or show its metadata and recorded objects."));

    app->in_pub = add_row(app, box, "Public key", "vigil.pub", 1);
    app->in_db  = add_row(app, box, "Baseline file", "baseline.vgl", 1);
    app->in_list = gtk_check_button_new_with_label("List every recorded object (show)");
    gtk_box_append(GTK_BOX(box), app->in_list);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_START);
    GtkWidget *vbtn = gtk_button_new_with_label("Verify signature");
    gtk_widget_add_css_class(vbtn, "go");
    g_signal_connect(vbtn, "clicked", G_CALLBACK(do_verify), app);
    app->run_btns.push_back(vbtn);
    GtkWidget *sbtn = gtk_button_new_with_label("Show baseline");
    gtk_widget_add_css_class(sbtn, "go2");
    g_signal_connect(sbtn, "clicked", G_CALLBACK(do_show), app);
    app->run_btns.push_back(sbtn);
    gtk_box_append(GTK_BOX(row), vbtn);
    gtk_box_append(GTK_BOX(row), sbtn);
    gtk_box_append(GTK_BOX(box), row);
    return box;
}

// ---------------------------------------------------------------------------
// About
// ---------------------------------------------------------------------------
static void on_about_clicked(GtkButton *, gpointer data) {
    App *app = (App *)data;
    GtkAboutDialog *about = GTK_ABOUT_DIALOG(gtk_about_dialog_new());
    gtk_window_set_transient_for(GTK_WINDOW(about), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(about), TRUE);
    gtk_about_dialog_set_program_name(about, "Vigil");
    gtk_about_dialog_set_version(about, VIGIL_VERSION);
    gtk_about_dialog_set_logo_icon_name(about, "vigil");
    gtk_about_dialog_set_comments(about,
        "Post-quantum file-integrity monitor for Linux.\n"
        "Know exactly what changed, and prove the record wasn't touched.");
    gtk_about_dialog_set_website(about, "https://github.com/effjy/vigil/");
    gtk_about_dialog_set_website_label(about, "Repository");
    gtk_about_dialog_set_license_type(about, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_copyright(about, "© 2026 Jean-Francois Lachance-Caumartin");
    const char *authors[] = { "Jean-Francois Lachance-Caumartin", nullptr };
    gtk_about_dialog_set_authors(about, authors);
    gtk_window_present(GTK_WINDOW(about));
}

// ---------------------------------------------------------------------------
// Theme — dark, neon-green / cyan "post-quantum" accents
// ---------------------------------------------------------------------------
static const char *CSS =
    "window { background-color: #0d0f14; color: #c5d1de; }"
    ".title { font-weight: bold; font-size: 18px; color: #39ff14; }"
    ".sub   { color: #4a5568; font-size: 11px; }"
    ".ok    { color: #39ff14; }"
    ".bad   { color: #ff5f6d; }"
    ".warn  { color: #ffd166; }"
    ".busy  { color: #00e5ff; }"
    ".dim   { color: #5a6678; }"
    ".hdr   { color: #00e5ff; font-weight: bold; }"
    ".field { color: #8a97a8; }"
    ".intro { color: #7d8aa0; font-size: 12px; }"
    "stackswitcher button { background: transparent; border: none; color: #8a97a8;"
    "  border-radius: 0; padding: 8px 14px; }"
    "stackswitcher button:checked { color: #39ff14;"
    "  box-shadow: inset 0 -2px 0 #39ff14; }"
    "entry { background: #161a22; color: #d7e0ea; border: 1px solid #232a36;"
    "  border-radius: 6px; padding: 5px 8px; }"
    "entry:focus-within { border-color: #00e5ff; }"
    "dropdown, dropdown button { background: #161a22; color: #d7e0ea;"
    "  border: 1px solid #232a36; border-radius: 6px; }"
    "checkbutton { color: #b3bdca; }"
    "textview, textview text { background-color: #0a0c10; color: #aeb9c7;"
    "  font-family: monospace; font-size: 12px; }"
    "button { background: #1a1f29; color: #c5d1de; border: 1px solid #2a323f;"
    "  border-radius: 6px; padding: 6px 14px; }"
    "button:hover { background: #222a36; }"
    "button:disabled { color: #4a5568; }"
    "button.go { color: #39ff14; border-color: #39ff14; font-weight: bold; }"
    "button.go:hover { background: #39ff14; color: #0a0c10; }"
    "button.go2 { color: #00e5ff; border-color: #00e5ff; font-weight: bold; }"
    "button.go2:hover { background: #00e5ff; color: #0a0c10; }"
    "button.stop { color: #ff5f6d; border-color: #ff5f6d; }"
    "button.stop:hover { background: #ff5f6d; color: #0a0c10; }";

static void apply_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_string(p, CSS);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

// ---------------------------------------------------------------------------
// Tray + minimize/close-to-tray (mirrors Warden)
// ---------------------------------------------------------------------------
static void present_front(App *app) {
    if (!app->window) return;
    gtk_widget_set_visible(app->window, TRUE);
    gtk_window_unminimize(GTK_WINDOW(app->window));
#ifdef GDK_WINDOWING_X11
    GdkSurface *surf = gtk_native_get_surface(GTK_NATIVE(app->window));
    if (surf && GDK_IS_X11_SURFACE(surf))
        gdk_x11_surface_set_user_time(surf, gdk_x11_get_server_time(surf));
#endif
    gtk_window_present(GTK_WINDOW(app->window));
}

static void tray_show_cb(void *user) { present_front((App *)user); }
static void tray_quit_cb(void *user) {
    App *app = (App *)user;
    if (app->proc) g_subprocess_force_exit(app->proc);
    g_application_quit(G_APPLICATION(app->app));
}

static gboolean on_window_close(GtkWindow *win, gpointer data) {
    App *app = (App *)data;
    if (app->tray_active) { gtk_widget_set_visible(GTK_WIDGET(win), FALSE); return TRUE; }
    return FALSE;
}

static void on_surface_state(GdkToplevel *tl, GParamSpec *, gpointer data) {
    App *app = (App *)data;
    if (!app->tray_active || !app->window) return;
    if (gdk_toplevel_get_state(tl) & GDK_TOPLEVEL_STATE_MINIMIZED)
        gtk_widget_set_visible(app->window, FALSE);
}

static void on_window_realize(GtkWidget *w, gpointer data) {
    GdkSurface *s = gtk_native_get_surface(GTK_NATIVE(w));
    if (s && GDK_IS_TOPLEVEL(s))
        g_signal_connect(s, "notify::state", G_CALLBACK(on_surface_state), data);
}

// ---------------------------------------------------------------------------
// Locate the `vigil` binary: PATH first, then next to this executable.
// ---------------------------------------------------------------------------
static std::string resolve_vigil(void) {
    char *p = g_find_program_in_path("vigil");
    if (p) { std::string s = p; g_free(p); return s; }
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        std::string dir = dirname(buf);
        std::string cand = dir + "/vigil";
        if (access(cand.c_str(), X_OK) == 0) return cand;
    }
    return "vigil";  // last resort; spawn will report if it's missing
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------
static void activate(GtkApplication *gapp, gpointer data) {
    App *app = (App *)data;
    if (app->window) { present_front(app); return; }

    apply_css();
    app->vigil_bin = resolve_vigil();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "Vigil");
    // Sized to fit comfortably on small (1366×768) laptop displays.
    gtk_window_set_default_size(GTK_WINDOW(app->window), 860, 540);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "vigil");

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(app->window), root);

    // Header
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_top(header, 12); gtk_widget_set_margin_bottom(header, 8);
    gtk_widget_set_margin_start(header, 16); gtk_widget_set_margin_end(header, 16);
    GtkWidget *titlebox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *title = gtk_label_new("VIGIL");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_add_css_class(title, "title");
    GtkWidget *sub = gtk_label_new("post-quantum file-integrity monitor");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0);
    gtk_widget_add_css_class(sub, "sub");
    gtk_box_append(GTK_BOX(titlebox), title);
    gtk_box_append(GTK_BOX(titlebox), sub);
    gtk_widget_set_hexpand(titlebox, TRUE);

    app->status_lbl = gtk_label_new("Ready");
    gtk_widget_add_css_class(app->status_lbl, "sub");
    gtk_widget_set_valign(app->status_lbl, GTK_ALIGN_CENTER);

    app->stop_btn = gtk_button_new_with_label("Stop");
    gtk_widget_add_css_class(app->stop_btn, "stop");
    gtk_widget_set_valign(app->stop_btn, GTK_ALIGN_CENTER);
    gtk_widget_set_sensitive(app->stop_btn, FALSE);
    g_signal_connect(app->stop_btn, "clicked", G_CALLBACK(on_stop_clicked), app);

    GtkWidget *about_btn = gtk_button_new_with_label("About");
    gtk_widget_set_valign(about_btn, GTK_ALIGN_CENTER);
    g_signal_connect(about_btn, "clicked", G_CALLBACK(on_about_clicked), app);

    gtk_box_append(GTK_BOX(header), titlebox);
    gtk_box_append(GTK_BOX(header), app->status_lbl);
    gtk_box_append(GTK_BOX(header), app->stop_btn);
    gtk_box_append(GTK_BOX(header), about_btn);
    gtk_box_append(GTK_BOX(root), header);

    // Operation pages
    app->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app->stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    GtkWidget *switcher = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(app->stack));
    gtk_widget_set_halign(switcher, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(root), switcher);

    gtk_stack_add_titled(GTK_STACK(app->stack), build_keygen_page(app),   "keygen",   "Keygen");
    gtk_stack_add_titled(GTK_STACK(app->stack), build_baseline_page(app), "baseline", "Baseline");
    gtk_stack_add_titled(GTK_STACK(app->stack), build_check_page(app),    "check",    "Check");
    gtk_stack_add_titled(GTK_STACK(app->stack), build_watch_page(app),    "watch",    "Watch");
    gtk_stack_add_titled(GTK_STACK(app->stack), build_inspect_page(app),  "inspect",  "Inspect");
    gtk_box_append(GTK_BOX(root), app->stack);

    // Activity log
    GtkWidget *logsep = gtk_label_new("Activity");
    gtk_label_set_xalign(GTK_LABEL(logsep), 0.0);
    gtk_widget_add_css_class(logsep, "field");
    gtk_widget_set_margin_start(logsep, 16); gtk_widget_set_margin_top(logsep, 4);
    gtk_box_append(GTK_BOX(root), logsep);

    app->log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->log_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->log_view), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app->log_view), 8);
    GtkTextBuffer *lb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->log_view));
    gtk_text_buffer_create_tag(lb, "ok",   "foreground", "#39ff14", nullptr);
    gtk_text_buffer_create_tag(lb, "bad",  "foreground", "#ff5f6d", nullptr);
    gtk_text_buffer_create_tag(lb, "warn", "foreground", "#ffd166", nullptr);
    gtk_text_buffer_create_tag(lb, "hdr",  "foreground", "#00e5ff", "weight", PANGO_WEIGHT_BOLD, nullptr);
    gtk_text_buffer_create_tag(lb, "dim",  "foreground", "#5a6678", nullptr);
    GtkTextIter e; gtk_text_buffer_get_end_iter(lb, &e);
    app->log_end = gtk_text_buffer_create_mark(lb, "log-end", &e, FALSE);

    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), app->log_view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_set_size_request(scroll, -1, 90);
    gtk_widget_set_margin_start(scroll, 12); gtk_widget_set_margin_end(scroll, 12);
    gtk_widget_set_margin_bottom(scroll, 12); gtk_widget_set_margin_top(scroll, 2);
    gtk_box_append(GTK_BOX(root), scroll);

    // Tray
    app->tray_active = tray_init(G_APPLICATION(gapp), "vigil",
                                 tray_show_cb, tray_quit_cb, app);
    g_signal_connect(app->window, "close-request", G_CALLBACK(on_window_close), app);
    g_signal_connect(app->window, "realize", G_CALLBACK(on_window_realize), app);

    log_raw(app, "Vigil ready. Pick an operation above.", "dim");
    if (app->tray_active)
        log_raw(app, "Tray icon active — minimizing or closing sends Vigil to the tray.", "dim");
    log_raw(app, std::string("Using binary: ") + app->vigil_bin, "dim");

    present_front(app);
}

int main(int argc, char **argv) {
    App app;
    app.app = gtk_application_new("com.github.effjy.vigil", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app.app, "activate", G_CALLBACK(activate), &app);
    int status = g_application_run(G_APPLICATION(app.app), argc, argv);
    if (app.proc) g_subprocess_force_exit(app.proc);
    g_object_unref(app.app);
    return status;
}
