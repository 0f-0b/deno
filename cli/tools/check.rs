// Copyright 2018-2026 the Deno authors. MIT license.

use std::sync::Arc;

use deno_core::error::AnyError;
use deno_terminal::colors;

use crate::args::CheckFlags;
use crate::args::Flags;
use crate::factory::CliFactory;
use crate::util::extract::extract_snippet_files;
use crate::util::file_watcher;

pub async fn check(
  flags: Arc<Flags>,
  check_flags: CheckFlags,
) -> Result<(), AnyError> {
  if let Some(watch_flags) = &flags.watch {
    let no_clear_screen = watch_flags.no_clear_screen;
    file_watcher::watch_func(
      flags,
      file_watcher::PrintConfig::new("Check", !no_clear_screen),
      move |flags, watcher_communicator, changed_paths| {
        let check_flags = check_flags.clone();
        watcher_communicator.show_path_changed(changed_paths);
        Ok(async move {
          let factory = CliFactory::from_flags_for_watcher(
            flags,
            watcher_communicator.clone(),
          );
          check_with_factory(&factory, check_flags).await
        })
      },
    )
    .await
  } else {
    let factory = CliFactory::from_flags(flags);
    check_with_factory(&factory, check_flags).await
  }
}

async fn check_with_factory(
  factory: &CliFactory,
  check_flags: CheckFlags,
) -> Result<(), AnyError> {
  let graph_container = factory.main_module_graph_container().await?;
  let mut roots = graph_container.collect_specifiers(
    &check_flags.files,
    crate::graph_container::CollectSpecifiersOptions {
      include_ignored_specified: false,
    },
  )?;
  if roots.is_empty() {
    log::warn!("{} No matching files found.", colors::yellow("Warning"));
    return Ok(());
  }

  if check_flags.doc || check_flags.doc_only {
    let file_fetcher = factory.file_fetcher()?;
    let root_permissions = factory.root_permissions_container()?;
    let specifiers = roots.clone();

    if check_flags.doc_only {
      roots.clear();
    }

    for s in specifiers {
      let file = file_fetcher.fetch(&s, root_permissions).await?;
      for snippet_file in extract_snippet_files(file)? {
        roots.push(snippet_file.url.clone());
        file_fetcher.insert_memory_files(snippet_file);
      }
    }
  }

  graph_container
    .check_specifiers(
      &roots,
      crate::graph_container::CheckSpecifiersOptions {
        allow_unknown_media_types: true,
        ..Default::default()
      },
    )
    .await
}
