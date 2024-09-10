void c(void) {
    /* do nothing */
}

void b(void) {
    c();
}

void a(void) {
    b();
}

int main(void) {
    a();
    return 0;
}


