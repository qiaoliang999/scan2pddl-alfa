(define (problem dmz_lan_motivating_example)
  (:domain alfa_chains)
  (:objects
    attacker_host db_server web_server - Host
    agent - Agent
    dmz lan - Network
    LOW_PRIVILEGES HIGH_PRIVILEGES ROOT_PRIVILEGES - Privilege
    a--apache--couchdb a--drupal--drupal a--php--php o--canonical--ubuntu_linux o--linux--linux_kernel - Product
    ma16 ma2 ma4 ma7 ma8 - Major
    mi0 mi4 mi6 mi8 - Minor
    pa0 pa33 pa9 - Patch
  )
  (:init
    (is_compromised attacker_host agent ROOT_PRIVILEGES)
    (connected_to_network attacker_host dmz)
    ;; db_server (10.10.20.10)
    (connected_to_network db_server lan)
    (has_product db_server a--apache--couchdb)
    (has_product db_server o--linux--linux_kernel)
    (has_version db_server a--apache--couchdb ma2 mi0 pa0)
    (has_version db_server o--linux--linux_kernel ma4 mi8 pa0)
    (TCP_listen db_server a--apache--couchdb)
    ;; web_server (10.10.10.10)
    (connected_to_network web_server dmz)
    (connected_to_network web_server lan)
    (has_product web_server a--drupal--drupal)
    (has_product web_server a--php--php)
    (has_product web_server o--canonical--ubuntu_linux)
    (has_version web_server a--drupal--drupal ma8 mi6 pa9)
    (has_version web_server a--php--php ma7 mi0 pa33)
    (has_version web_server o--canonical--ubuntu_linux ma16 mi4 pa0)
    (TCP_listen web_server a--drupal--drupal)
    (TCP_listen web_server a--php--php)
  )
  (:goal
    (is_compromised db_server agent ROOT_PRIVILEGES)
  )
)
